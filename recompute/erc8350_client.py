#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""
An independent ERC-8350 client: the registry's hashing, commitments and state
machine, written from the specification and checked against its published
conformance vectors.

WHAT THIS IS

  A second implementation of the ERC-8350 core registry, held in memory. It
  was written from the official Draft (ethereum/ERCs @ b9651bc) and the
  published vector files. No code, package or generated constant from the
  reference repository is used. Every constant here is derived from the type
  strings and domain tags in the Draft; the vector files are what the
  derivations are checked against, never a source of values.

  Results are reported per layer, each PASS or FAIL on its own:

    spec      every ERC-8350 type string and domain tag embedded below occurs
              verbatim in the pinned Draft, so the constants are consumed by a
              check rather than trusted. The EIP712Domain type comes from
              EIP-712, not this Draft; the published domain separators back it;
    hash      typehashes, spaceId, transitionId, nextStateRoot, registration
              and authorization-update struct hashes, domain separator,
              signing digests, and the three baseline commitments rebuilt
              from their disclosed witnesses, for v1 and v2;
    fixture   the v2 five-transition chain and the Sepolia fixture replayed
              offline from genesis, each nextStateRoot feeding the next
              prevStateRoot;
    state     the registry state machine. The v2 Space is registered and its
              chain committed through it, each event checked field for field
              against the Draft's own event declarations,
              then each of the 12 v2 rejections is executed against that held
              state, and the head, the authorization record, the stored
              transitions and the event log are compared before and after.
              A refusal must come from the rule the case names, except for
              the two v2 inputs that break more than one rule; single-defect
              cases cover those rules;
    ecdsa     EOA authorization for all three operations, which the vectors
              leave unsigned, driven with this file's public test keys on a
              chain and registry other than v2's: who may authorize each
              operation (and who may not), empty signatures from relayers,
              registration front-running, high-s, bad v, r/s out of range,
              compact and padded encodings, cross-chain and cross-registry
              replay, self-call with bad bytes, controller and authorizer
              rotation, rotation replay and zero replacements, direct calls.
              --emit-signature-vectors writes the cases out as static vectors,
              and only after a run in which every layer passed;
    compat    reference compatibility, not a normative claim: each rejection's
              error name, ABI selector and arguments against the ones the
              vectors publish (AQ-05 in the reference's open questions).

DECLARED CAPABILITIES

  direct-empty   ENABLED for registration, rotation and transition. The Draft
                 makes it MAY. An empty signature authorizes only when the
                 caller is exactly the required account; non-empty bytes from
                 that account are still validated.
  ecdsa          65-byte r || s || v, v in {27, 28}, 0 < r < n, 0 < s <= n/2,
                 recovered address equal to the required account. Any other
                 length is refused before recovery.
  erc-1271       NOT SUPPORTED. Accounts are modelled without code. An
                 operation that reaches signature validation for an account
                 with code raises Unsupported: it is neither accepted nor
                 rejected on a guess. EIP-7702 delegated accounts and Safe
                 policies fall under the same line.

WHAT THIS DOES NOT COVER

  * Contract-account authorization (above), so the reference's AQ-01 (empty
    and custom ERC-1271 signatures) and AQ-03 (malformed 1271 return data) do
    not arise here. On AQ-02 the client follows the reading the reference's
    decision table describes: each operation's required account, and
    non-empty bytes from that account still validated.
  * Deployed-code identity and the immutability requirement. Those are
    properties of a deployment; erc8350_sepolia.py checks the public one
    against live chain state.
  * Gas, liveness and relayer behaviour.
  * TransitionAlreadyExists has no vector because no input reaches it: the id
    binds sequence and prevStateRoot, both checked against the head first.
    The guard is still here, so a duplicate can never overwrite a record.

USAGE

    pip install pycryptodome==3.23.0
    python3 erc8350_client.py                     # fetch pinned inputs, check digests, run
    python3 erc8350_client.py --inputs DIR        # local copies; digests still enforced
    python3 erc8350_client.py --json report.json  # machine-readable result record
    python3 erc8350_client.py --emit-signature-vectors sigs.json

  Inputs are pinned by commit and SHA-256 below. A file whose digest differs
  is refused before any check runs. Exit 0 only when every layer passes.
"""

import argparse
import copy
import hashlib
import hmac
import json
import platform
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

try:
    import Crypto
    from Crypto.Hash import keccak
except ImportError:
    sys.exit("needs pycryptodome:  pip install pycryptodome==3.23.0")

# ---------------------------------------------------------------------- inputs
DRAFT_COMMIT = "b9651bc84714e87e6361f4f6c0c8ff39cc265d0a"
VECTORS_COMMIT = "aa9bbe5192cb7fd34789b71d928b444605227a0f"

INPUTS = {
    "erc-8350.md": (
        f"https://raw.githubusercontent.com/ethereum/ERCs/{DRAFT_COMMIT}/ERCS/erc-8350.md",
        "9aa44fe3854a7ae553cc77a5a59c072f36a405869a7d3c5e082addbda3d995ca"),
    "v1.json": (
        f"https://raw.githubusercontent.com/AwareLiquid/AgentMemoryState/{VECTORS_COMMIT}/test-vectors/v1.json",
        "5e04cb9c1181222f483d3ad547e0a9aa301dfab74c7028f3cfa2e5dcd574fc20"),
    "v2.json": (
        f"https://raw.githubusercontent.com/AwareLiquid/AgentMemoryState/{VECTORS_COMMIT}/test-vectors/v2.json",
        "4c59351ffe5317434c8ad8fda88cb95c2d2158f3dd6c147c301b7496de8dce4e"),
    "sepolia-fixture-v1.json": (
        f"https://raw.githubusercontent.com/AwareLiquid/AgentMemoryState/{VECTORS_COMMIT}/test-vectors/sepolia-fixture-v1.json",
        "3d6695d86dfceb4dac96848cd955dedfa28aedcf86a7d8b5ce0d6e3cb856bde9"),
}


def _fetch(url: str) -> bytes:
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return resp.read()
        except OSError as exc:
            last = exc
            time.sleep(1 + attempt)
    raise RuntimeError(f"fetch failed: {url}: {last}")


def load_inputs(directory=None) -> dict:
    """Read or fetch every pinned input and refuse any digest mismatch."""
    out = {}
    for name, (url, want) in INPUTS.items():
        raw = (Path(directory) / name).read_bytes() if directory else _fetch(url)
        got = hashlib.sha256(raw).hexdigest()
        if got != want:
            raise RuntimeError(f"{name}: sha256 {got} does not match the pin {want}")
        out[name] = raw
    return out


# --------------------------------------------------------------------- hashing
def k256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def hexs(data: bytes) -> str:
    return "0x" + data.hex()


def b32(value) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if len(raw) != 32:
        raise ValueError(f"expected 32 bytes, got {len(raw)}")
    return raw


def addr(value) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if len(raw) != 20:
        raise ValueError(f"expected a 20-byte address, got {len(raw)}")
    return raw


def enc_addr(a: bytes) -> bytes:
    return b"\x00" * 12 + addr(a)


def enc_uint(n: int, bits: int) -> bytes:
    if not 0 <= n < (1 << bits):
        raise ValueError(f"{n} does not fit uint{bits}")
    return n.to_bytes(32, "big")


ZERO32 = b"\x00" * 32
ZERO20 = b"\x00" * 20

# ERC-8350 Specification, byte for byte. The spec layer re-finds each of these
# in the pinned Draft text.
MEMORY_SPACE_TYPE = "MemorySpace(address initialController,bytes32 salt)"
EXPERIENCE_DELTA_TYPE = (
    "ExperienceDelta(bytes32 spaceId,uint64 sequence,bytes32 prevStateRoot,"
    "bytes32 deltaCommitment,bytes32 provenanceCommitment,bytes32 profileId,"
    "bytes32 locatorCommitment)")
MEMORY_STATE_TYPE = "MemoryState(bytes32 prevStateRoot,bytes32 transitionId)"
SPACE_REGISTRATION_TYPE = (
    "SpaceRegistration(bytes32 spaceId,address controller,address authorizer)")
SPACE_AUTHORIZATION_TYPE = (
    "SpaceAuthorization(bytes32 spaceId,address newController,"
    "address newAuthorizer,uint64 nonce)")
DELTA_DOMAIN_TAG = "AgentMemoryState.deltaCommitment.v1"
PROVENANCE_DOMAIN_TAG = "AgentMemoryState.provenanceCommitment.v1"
LOCATOR_DOMAIN_TAG = "AgentMemoryState.locatorCommitment.v1"
DOMAIN_NAME = "AgentMemoryState"
DOMAIN_VERSION = "1"

# EIP-712's own domain type, restricted to the four fields ERC-8350 names.
EIP712_DOMAIN_TYPE = (
    "EIP712Domain(string name,string version,uint256 chainId,"
    "address verifyingContract)")

MEMORY_SPACE_TYPEHASH = k256(MEMORY_SPACE_TYPE.encode())
EXPERIENCE_DELTA_TYPEHASH = k256(EXPERIENCE_DELTA_TYPE.encode())
MEMORY_STATE_TYPEHASH = k256(MEMORY_STATE_TYPE.encode())
SPACE_REGISTRATION_TYPEHASH = k256(SPACE_REGISTRATION_TYPE.encode())
SPACE_AUTHORIZATION_TYPEHASH = k256(SPACE_AUTHORIZATION_TYPE.encode())
EIP712_DOMAIN_TYPEHASH = k256(EIP712_DOMAIN_TYPE.encode())
DELTA_DOMAIN = k256(DELTA_DOMAIN_TAG.encode())
PROVENANCE_DOMAIN = k256(PROVENANCE_DOMAIN_TAG.encode())
LOCATOR_DOMAIN = k256(LOCATOR_DOMAIN_TAG.encode())


@dataclass(frozen=True)
class Delta:
    space_id: bytes
    sequence: int
    prev_state_root: bytes
    delta_commitment: bytes
    provenance_commitment: bytes
    profile_id: bytes
    locator_commitment: bytes

    @classmethod
    def from_json(cls, d: dict) -> "Delta":
        return cls(b32(d["spaceId"]), int(d["sequence"]), b32(d["prevStateRoot"]),
                   b32(d["deltaCommitment"]), b32(d["provenanceCommitment"]),
                   b32(d["profileId"]), b32(d["locatorCommitment"]))


def space_id_of(initial_controller: bytes, salt: bytes) -> bytes:
    return k256(MEMORY_SPACE_TYPEHASH + enc_addr(initial_controller) + b32(salt))


def transition_id_of(d: Delta) -> bytes:
    return k256(EXPERIENCE_DELTA_TYPEHASH + d.space_id + enc_uint(d.sequence, 64)
                + d.prev_state_root + d.delta_commitment
                + d.provenance_commitment + d.profile_id + d.locator_commitment)


def next_state_root_of(prev_state_root: bytes, transition_id: bytes) -> bytes:
    return k256(MEMORY_STATE_TYPEHASH + b32(prev_state_root) + b32(transition_id))


def registration_hash(space_id: bytes, controller: bytes, authorizer: bytes) -> bytes:
    return k256(SPACE_REGISTRATION_TYPEHASH + b32(space_id)
                + enc_addr(controller) + enc_addr(authorizer))


def authorization_hash(space_id: bytes, new_controller: bytes,
                       new_authorizer: bytes, nonce: int) -> bytes:
    return k256(SPACE_AUTHORIZATION_TYPEHASH + b32(space_id)
                + enc_addr(new_controller) + enc_addr(new_authorizer)
                + enc_uint(nonce, 64))


def domain_separator(chain_id: int, verifying_contract: bytes) -> bytes:
    return k256(EIP712_DOMAIN_TYPEHASH + k256(DOMAIN_NAME.encode())
                + k256(DOMAIN_VERSION.encode()) + enc_uint(chain_id, 256)
                + enc_addr(verifying_contract))


def signing_digest(domain: bytes, struct_hash: bytes) -> bytes:
    return k256(b"\x19\x01" + b32(domain) + b32(struct_hash))


def delta_commitment_of(profile_id: bytes, salt: bytes, payload: bytes) -> bytes:
    return k256(DELTA_DOMAIN + b32(profile_id) + b32(salt) + k256(payload))


def provenance_commitment_of(salt: bytes, provenance: bytes) -> bytes:
    return k256(PROVENANCE_DOMAIN + b32(salt) + k256(provenance))


def locator_commitment_of(salt: bytes, locator: str) -> bytes:
    return k256(LOCATOR_DOMAIN + b32(salt) + k256(locator.encode("utf-8")))


# -------------------------------------------------------------------- secp256k1
# Affine arithmetic, written for clarity over speed; a run signs and recovers a
# few dozen times. None is the point at infinity.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = N // 2
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1] % P, -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow((b[0] - a[0]) % P, -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k: int, point):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        k >>= 1
    return acc


def _address_of_point(q) -> bytes:
    return k256(q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big"))[12:]


def address_of(private_key: int) -> bytes:
    return _address_of_point(_mul(private_key, G))


def _rfc6979_nonce(private_key: int, digest: bytes) -> int:
    x = private_key.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < N:
            return nonce
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(private_key: int, digest: bytes) -> bytes:
    """Deterministic (RFC 6979) low-s signature, r || s || v with v in {27, 28}."""
    z = int.from_bytes(digest, "big")
    nonce = _rfc6979_nonce(private_key, digest)
    r_point = _mul(nonce, G)
    if r_point[0] >= N:
        raise ValueError("R.x >= n; not encodable with v in {27, 28}")
    r = r_point[0]
    s = pow(nonce, -1, N) * (z + r * private_key) % N
    recid = r_point[1] & 1
    if s > HALF_N:
        s, recid = N - s, recid ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])


def _recover_raw(digest: bytes, r: int, s: int, recid: int):
    alpha = (r * r * r + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if y * y % P != alpha:
        return None
    if y & 1 != recid:
        y = P - y
    z = int.from_bytes(digest, "big") % N
    r_inv = pow(r, -1, N)
    q = _add(_mul(s * r_inv % N, (r, y)), _mul(-z * r_inv % N, G))
    return None if q is None else _address_of_point(q)


def _split(signature: bytes):
    return (int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"),
            signature[64])


def ecdsa_recover(digest: bytes, signature: bytes):
    """Signer of a canonical 65-byte signature, or None for anything else."""
    if len(signature) != 65:
        return None
    r, s, v = _split(signature)
    if v not in (27, 28) or not 0 < r < N or not 0 < s <= HALF_N:
        return None
    return _recover_raw(digest, r, s, v - 27)


def malleate(signature: bytes) -> bytes:
    """The other valid signature for the same key and digest: (r, n - s), with
    v moved to the opposite parity (27 <-> 28)."""
    r, s, v = _split(signature)
    return r.to_bytes(32, "big") + (N - s).to_bytes(32, "big") + bytes([55 - v])


# --------------------------------------------------------------- state machine
class Rejected(Exception):
    """A refusal the specification requires. `name` and `abi_signature` follow
    the reference's error names so they can be compared; `rule` cites the Draft;
    `code` names the rule that fired, finer than `name` where one reference
    error covers several rules (InvalidAuthorization: length, noncanonical,
    signer)."""

    def __init__(self, name: str, rule: str, args=(), types=(), code=None):
        super().__init__(f"{name}: {rule}")
        self.name, self.rule, self.values, self.types = name, rule, tuple(args), tuple(types)
        self.code = code or name

    @property
    def abi_signature(self) -> str:
        return f"{self.name}({','.join(self.types)})"


class Unsupported(Exception):
    """An authorization path this client declares it does not implement."""


@dataclass
class SpaceRecord:
    controller: bytes
    authorizer: bytes
    config_nonce: int
    head_transition_id: bytes
    head_state_root: bytes
    head_sequence: int


class Registry:
    """In-memory ERC-8350 registry. Every check precedes every write, so a
    rejection cannot leave a partial update behind; tests compare snapshots."""

    def __init__(self, chain_id: int, address: bytes, direct_empty: bool = True,
                 code: dict = None):
        self.chain_id = chain_id
        self.address = addr(address)
        self.domain = domain_separator(chain_id, self.address)
        self.direct_empty = direct_empty
        self.code = dict(code or {})
        self.spaces = {}
        self.transitions = {}
        self.events = []

    def snapshot(self):
        return copy.deepcopy((self.spaces, self.transitions, self.events))

    def head(self, space_id: bytes):
        rec = self._space(space_id)
        return rec.head_transition_id, rec.head_state_root, rec.head_sequence

    def space_authorization(self, space_id: bytes):
        rec = self._space(space_id)
        return rec.controller, rec.authorizer, rec.config_nonce

    def _space(self, space_id: bytes) -> SpaceRecord:
        rec = self.spaces.get(space_id)
        if rec is None:
            raise Rejected("UnknownSpace", "the Space is not registered, so it has "
                           "no controller or authorizer to authorize anything")
        return rec

    def _authorize(self, required: bytes, sender: bytes, struct_hash: bytes,
                   signature: bytes) -> str:
        if not signature and self.direct_empty and sender == required:
            return "direct-empty"
        if self.code.get(required):
            raise Unsupported("required account has code; ERC-1271 is not implemented")
        if len(signature) != 65:
            raise Rejected("InvalidAuthorization", "a signature of any other length "
                           "than 65 MUST be rejected without attempting recovery",
                           code="length")
        signer = ecdsa_recover(signing_digest(self.domain, struct_hash), signature)
        if signer is None:
            raise Rejected("InvalidAuthorization", "the signature MUST be canonical and "
                           "non-malleable: v 27 or 28, 0 < r < n, 0 < s <= n/2",
                           code="noncanonical")
        if signer != required:
            raise Rejected("InvalidAuthorization", "the recovered signer MUST equal the "
                           "configured account", code="signer")
        return "ecdsa"

    def register_space(self, sender, space_id, controller, authorizer, salt,
                       signature=b""):
        space_id, controller, authorizer = b32(space_id), addr(controller), addr(authorizer)
        if space_id == ZERO32:
            raise Rejected("ZeroSpaceId", "reference guard; a zero spaceId can never "
                           "equal deriveSpaceId(controller, salt)")
        if controller == ZERO20 or authorizer == ZERO20:
            raise Rejected("ZeroAddress", "registration MUST bind the Space to non-zero "
                           "controller and authorizer addresses")
        derived = space_id_of(controller, salt)
        if derived != space_id:
            raise Rejected("InvalidSpaceId", "the supplied spaceId MUST equal "
                           "deriveSpaceId(controller, salt)", (derived, space_id),
                           ("bytes32", "bytes32"))
        if space_id in self.spaces:
            raise Rejected("SpaceAlreadyRegistered", "a Memory Space MUST be "
                           "registered at most once")
        path = self._authorize(controller, addr(sender),
                               registration_hash(space_id, controller, authorizer),
                               signature)
        self.spaces[space_id] = SpaceRecord(controller, authorizer, 0, ZERO32, ZERO32, 0)
        self.events.append(("SpaceRegistered", space_id, controller, authorizer))
        return path

    def update_space_authorization(self, sender, space_id, new_controller,
                                   new_authorizer, signature=b""):
        space_id = b32(space_id)
        new_controller, new_authorizer = addr(new_controller), addr(new_authorizer)
        rec = self._space(space_id)
        if new_controller == ZERO20 or new_authorizer == ZERO20:
            raise Rejected("ZeroAddress", "both replacement addresses MUST be non-zero")
        nonce = rec.config_nonce + 1
        path = self._authorize(rec.controller, addr(sender),
                               authorization_hash(space_id, new_controller,
                                                  new_authorizer, nonce),
                               signature)
        rec.controller, rec.authorizer, rec.config_nonce = new_controller, new_authorizer, nonce
        self.events.append(("SpaceAuthorizationUpdated", space_id, new_controller,
                            new_authorizer, nonce))
        return path

    def commit_transition(self, sender, delta: Delta, signature=b""):
        rec = self._space(delta.space_id)
        if delta.delta_commitment == ZERO32:
            raise Rejected("ZeroDeltaCommitment", "deltaCommitment MUST NOT be zero")
        if delta.profile_id == ZERO32:
            raise Rejected("ZeroProfileId", "profileId MUST NOT be zero")
        if delta.sequence != rec.head_sequence + 1:
            raise Rejected("BadSequence", "accept only if sequence == currentSequence + 1",
                           (rec.head_sequence + 1, delta.sequence), ("uint64", "uint64"))
        if delta.prev_state_root != rec.head_state_root:
            raise Rejected("BadPreviousState", "accept only if prevStateRoot == "
                           "currentStateRoot", (rec.head_state_root, delta.prev_state_root),
                           ("bytes32", "bytes32"))
        tid = transition_id_of(delta)
        path = self._authorize(rec.authorizer, addr(sender), tid, signature)
        if (delta.space_id, tid) in self.transitions:
            raise Rejected("TransitionAlreadyExists", "a duplicate transitionId MUST "
                           "NOT overwrite a stored transition")
        root = next_state_root_of(delta.prev_state_root, tid)
        self.transitions[(delta.space_id, tid)] = (delta, root)
        rec.head_transition_id, rec.head_state_root, rec.head_sequence = tid, root, delta.sequence
        # The Draft's event, field for field.
        self.events.append(("TransitionCommitted", delta.space_id, tid, delta.sequence,
                            delta.prev_state_root, root, delta.delta_commitment,
                            delta.provenance_commitment, delta.profile_id,
                            delta.locator_commitment, rec.authorizer))
        return tid, root, path


# --------------------------------------------------------------------- reporting
LAYERS = ("spec", "hash", "fixture", "state", "ecdsa", "compat")


class Report:
    def __init__(self):
        self.checks = {layer: [] for layer in LAYERS}

    def check(self, layer: str, name: str, ok: bool, detail: str = ""):
        self.checks[layer].append({"check": name, "pass": bool(ok), "detail": detail})
        return ok

    def equal(self, layer: str, name: str, got, want):
        g = hexs(got) if isinstance(got, bytes) else str(got)
        w = hexs(want) if isinstance(want, bytes) else str(want)
        return self.check(layer, name, got == want,
                          g if got == want else f"got {g}, want {w}")

    def passed(self, layer: str) -> bool:
        return bool(self.checks[layer]) and all(c["pass"] for c in self.checks[layer])


def _bytes_or_none(text):
    return None if text is None else text.encode("utf-8")


def _witness_commitments(profile_id, payload, delta_salt, provenance,
                         provenance_salt, locator, locator_salt):
    dc = delta_commitment_of(profile_id, b32(delta_salt), payload)
    pc = ZERO32 if provenance is None else provenance_commitment_of(
        b32(provenance_salt), provenance)
    lc = ZERO32 if locator is None else locator_commitment_of(b32(locator_salt), locator)
    return dc, pc, lc


# ---------------------------------------------------------------- layer: spec
def _occurs_whole(text: str, draft: str) -> bool:
    """`text` appears as a complete token: not as a prefix of a longer type
    string or tag, nor with extra characters glued to its front."""
    pattern = r'(?:^|(?<=["`\s]))' + re.escape(text) + r'(?=["`\s]|$)'
    return re.search(pattern, draft, re.M) is not None


def draft_events(draft: str) -> dict:
    """Event name -> field names, in declaration order, from the Draft's interface."""
    return {m.group(1): [part.split()[-1] for part in m.group(2).split(",")]
            for m in re.finditer(r"event\s+(\w+)\(\s*(.*?)\);", draft, re.S)}


EVENT_FIELDS = {
    "SpaceRegistered": {"spaceId", "controller", "authorizer"},
    "SpaceAuthorizationUpdated": {"spaceId", "controller", "authorizer", "configNonce"},
    "TransitionCommitted": {"spaceId", "transitionId", "sequence", "prevStateRoot",
                            "nextStateRoot", "deltaCommitment", "provenanceCommitment",
                            "profileId", "locatorCommitment", "authorizer"},
}


def expected_event(events: dict, name: str, **values):
    """The event the Draft declares, built in the Draft's field order from named
    values, so an emitter with fields out of order cannot match it."""
    fields = events.get(name)
    if not fields or set(fields) != set(values):
        return ("<no matching Draft declaration>", name)
    return (name,) + tuple(values[f] for f in fields)


def run_spec(rep: Report, draft: str, v1: dict, v2: dict):
    embedded = {
        "MemorySpace type": MEMORY_SPACE_TYPE,
        "ExperienceDelta type": EXPERIENCE_DELTA_TYPE,
        "MemoryState type": MEMORY_STATE_TYPE,
        "SpaceRegistration type": SPACE_REGISTRATION_TYPE,
        "SpaceAuthorization type": SPACE_AUTHORIZATION_TYPE,
        "delta domain tag": DELTA_DOMAIN_TAG,
        "provenance domain tag": PROVENANCE_DOMAIN_TAG,
        "locator domain tag": LOCATOR_DOMAIN_TAG,
        "domain name": f'"{DOMAIN_NAME}"',
    }
    for label, text in embedded.items():
        rep.check("spec", f"Draft contains {label}", _occurs_whole(text, draft), text)
    events = draft_events(draft)
    for name, fields in EVENT_FIELDS.items():
        rep.check("spec", f"Draft declares event {name} with the fields this client emits",
                  set(events.get(name, ())) == fields, ", ".join(events.get(name, ["missing"])))
    version_line = any(line.split("=")[0].strip() == "version"
                       and line.split("=", 1)[1].strip() == f'"{DOMAIN_VERSION}"'
                       for line in draft.splitlines() if "=" in line)
    rep.check("spec", "Draft domain version", version_line, f'version = "{DOMAIN_VERSION}"')
    for key, text in (("memorySpace", MEMORY_SPACE_TYPE),
                      ("experienceDelta", EXPERIENCE_DELTA_TYPE),
                      ("memoryState", MEMORY_STATE_TYPE),
                      ("spaceRegistration", SPACE_REGISTRATION_TYPE)):
        rep.check("spec", f"v2 type string {key} matches the Draft",
                  v2["types"][key] == text)
    rep.check("spec", "v1 type string spaceAuthorization matches the Draft",
              v1["types"]["spaceAuthorization"] == SPACE_AUTHORIZATION_TYPE)
    for label, got, want in (
            ("ExperienceDelta", EXPERIENCE_DELTA_TYPEHASH, "0x4f020f86bc06d852f1fde17853b4d92a70214eeab8e09718028124af097d070d"),
            ("MemoryState", MEMORY_STATE_TYPEHASH, "0xf3148762556cbf851baf4b9a205e18ff4e6b366a58a3a1ef58e8626ba41beadb"),
            ("MemorySpace", MEMORY_SPACE_TYPEHASH, "0x9ae5478f084ad3b841da58a9cb2354d153cddec59ee64d0cb741fa9d08884531")):
        rep.check("spec", f"{label} typehash as printed in the Draft's Test Cases",
                  hexs(got) in draft and hexs(got) == want, hexs(got))


# ---------------------------------------------------------------- layer: hash
def run_hash(rep: Report, v1: dict, v2: dict):
    e1 = v1["expected"]
    rep.equal("hash", "v1 ExperienceDelta typehash", EXPERIENCE_DELTA_TYPEHASH,
              b32(e1["experienceDeltaTypehash"]))
    rep.equal("hash", "v1 MemoryState typehash", MEMORY_STATE_TYPEHASH,
              b32(e1["memoryStateTypehash"]))
    rep.equal("hash", "v1 MemorySpace typehash", MEMORY_SPACE_TYPEHASH,
              b32(e1["memorySpaceTypehash"]))
    c = v1["commitment"]
    profile = b32(c["profileId"])
    dc, pc, lc = _witness_commitments(profile, c["payload"].encode("utf-8"),
                                      c["deltaSalt"], _bytes_or_none(c["provenance"]),
                                      c["provenanceSalt"], c["locator"], c["locatorSalt"])
    rep.equal("hash", "v1 deltaCommitment from witness", dc, b32(c["deltaCommitment"]))
    rep.equal("hash", "v1 provenanceCommitment from witness", pc,
              b32(c["provenanceCommitment"]))
    rep.equal("hash", "v1 locatorCommitment from witness", lc, b32(c["locatorCommitment"]))
    d1 = Delta.from_json(v1["delta"])
    rep.check("hash", "v1 delta carries the rebuilt commitments",
              (d1.delta_commitment, d1.provenance_commitment, d1.locator_commitment,
               d1.profile_id) == (dc, pc, lc, profile))
    sa = v1["spaceAuthorization"]
    sid = space_id_of(addr(sa["controller"]), b32(sa["spaceSalt"]))
    rep.equal("hash", "v1 spaceId", sid, d1.space_id)
    tid = transition_id_of(d1)
    rep.equal("hash", "v1 transitionId", tid, b32(e1["transitionId"]))
    rep.equal("hash", "v1 nextStateRoot", next_state_root_of(d1.prev_state_root, tid),
              b32(e1["nextStateRoot"]))
    dom = v1["eip712"]
    rep.check("hash", "v1 domain name and version", (dom["name"], dom["version"])
              == (DOMAIN_NAME, DOMAIN_VERSION))
    sep = domain_separator(int(dom["chainId"]), addr(dom["verifyingContract"]))
    rep.equal("hash", "v1 domainSeparator", sep, b32(dom["domainSeparator"]))
    rep.equal("hash", "v1 signingDigest", signing_digest(sep, tid), b32(dom["signingDigest"]))
    rep.equal("hash", "v1 registrationId (SpaceRegistration struct hash)",
              registration_hash(sid, addr(sa["controller"]), addr(sa["authorizer"])),
              b32(sa["registrationId"]))
    rep.equal("hash", "v1 authorizationId (SpaceAuthorization struct hash)",
              authorization_hash(sid, addr(sa["newController"]), addr(sa["newAuthorizer"]),
                                 int(sa["updateNonce"])),
              b32(sa["authorizationId"]))

    th = v2["typehashes"]
    rep.equal("hash", "v2 ExperienceDelta typehash", EXPERIENCE_DELTA_TYPEHASH,
              b32(th["experienceDelta"]))
    rep.equal("hash", "v2 MemoryState typehash", MEMORY_STATE_TYPEHASH, b32(th["memoryState"]))
    rep.equal("hash", "v2 MemorySpace typehash", MEMORY_SPACE_TYPEHASH, b32(th["memorySpace"]))
    dom2 = v2["eip712"]
    rep.check("hash", "v2 domain name and version", (dom2["name"], dom2["version"])
              == (DOMAIN_NAME, DOMAIN_VERSION))
    sep2 = domain_separator(int(dom2["chainId"]), addr(dom2["verifyingContract"]))
    rep.equal("hash", "v2 domainSeparator", sep2, b32(dom2["domainSeparator"]))
    sp = v2["space"]
    sid2 = space_id_of(addr(sp["controller"]), b32(sp["salt"]))
    rep.equal("hash", "v2 spaceId", sid2, b32(sp["spaceId"]))
    rep.equal("hash", "v2 registrationId",
              registration_hash(sid2, addr(sp["controller"]), addr(sp["authorizer"])),
              b32(sp["registrationId"]))
    for entry in v2["chain"]:
        d, w, x = Delta.from_json(entry["delta"]), entry["witness"], entry["expected"]
        label = f"v2 {entry['label']}"
        rep.check("hash", f"{label} payload encoding is utf-8",
                  w["payloadEncoding"] == "utf-8")
        dc, pc, lc = _witness_commitments(d.profile_id, w["payload"].encode("utf-8"),
                                          w["deltaSalt"], _bytes_or_none(w["provenance"]),
                                          w["provenanceSalt"], w["locator"], w["locatorSalt"])
        rep.equal("hash", f"{label} deltaCommitment", dc, d.delta_commitment)
        rep.equal("hash", f"{label} provenanceCommitment", pc, d.provenance_commitment)
        rep.equal("hash", f"{label} locatorCommitment", lc, d.locator_commitment)
        tid = transition_id_of(d)
        rep.equal("hash", f"{label} transitionId", tid, b32(x["transitionId"]))
        rep.equal("hash", f"{label} nextStateRoot", next_state_root_of(d.prev_state_root, tid),
                  b32(x["nextStateRoot"]))
        rep.equal("hash", f"{label} signingDigest", signing_digest(sep2, tid),
                  b32(x["signingDigest"]))
    ref = v2["v1Reference"]
    rep.check("hash", "v2 v1Reference restates v1",
              (b32(ref["transitionId"]), b32(ref["nextStateRoot"]), b32(ref["domainSeparator"]))
              == (b32(e1["transitionId"]), b32(e1["nextStateRoot"]), b32(dom["domainSeparator"])))
    rep.check("hash", "v2 and v1 share one spaceId", (sid2 == d1.space_id)
              == bool(ref["sameSpaceIdAsV1"]))


# ------------------------------------------------------------- layer: fixture
def _replay(rep: Report, label: str, space_id: bytes, entries):
    """Walk a chain from genesis; entries are (Delta, transitionId, nextStateRoot)."""
    prev, ok = ZERO32, True
    for i, (d, want_tid, want_root) in enumerate(entries, start=1):
        ok &= rep.check("fixture", f"{label} #{i} spaceId", d.space_id == space_id)
        ok &= rep.check("fixture", f"{label} #{i} sequence is {i}", d.sequence == i,
                        str(d.sequence))
        ok &= rep.check("fixture", f"{label} #{i} prevStateRoot links", d.prev_state_root == prev,
                        hexs(d.prev_state_root))
        tid = transition_id_of(d)
        prev = next_state_root_of(prev, tid)
        ok &= rep.equal("fixture", f"{label} #{i} transitionId", tid, want_tid)
        ok &= rep.equal("fixture", f"{label} #{i} nextStateRoot", prev, want_root)
    return prev, len(entries), ok


def run_fixture(rep: Report, v2: dict, fx: dict):
    entries = [(Delta.from_json(e["delta"]), b32(e["expected"]["transitionId"]),
                b32(e["expected"]["nextStateRoot"])) for e in v2["chain"]]
    head, count, _ = _replay(rep, "v2 chain", b32(v2["space"]["spaceId"]), entries)
    rep.check("fixture", "v2 chain head", count == 5, f"sequence {count}, root {hexs(head)}")

    net, sp = fx["network"], fx["space"]
    sid = space_id_of(addr(sp["controller"]), b32(sp["salt"]))
    rep.equal("fixture", "Sepolia fixture spaceId from controller and salt", sid,
              b32(sp["spaceId"]))
    entries = []
    for i, t in enumerate(fx["transitions"], start=1):
        d, w = Delta.from_json(t["delta"]), t["witness"]
        dc, pc, lc = _witness_commitments(d.profile_id, w["payload_jcs"].encode("utf-8"),
                                          w["delta_salt"],
                                          _bytes_or_none(w["provenance_bytes_utf8"]),
                                          w["provenance_salt"], w["locator"], w["locator_salt"])
        rep.check("fixture", f"Sepolia fixture #{i} commitments from witness",
                  (dc, pc, lc) == (d.delta_commitment, d.provenance_commitment,
                                   d.locator_commitment))
        entries.append((d, b32(t["transitionId"]), b32(t["nextStateRoot"])))
    head, count, _ = _replay(rep, "Sepolia fixture", sid, entries)
    sep = domain_separator(int(net["chainId"]), addr(net["registry"]))
    rep.check("fixture", "Sepolia fixture head", count == 5,
              f"chainId {net['chainId']}, registry {net['registry']}, sequence {count}, "
              f"root {hexs(head)}, domainSeparator {hexs(sep)} (not published; "
              f"signature checks need chain state)")


# --------------------------------------------------------------- layer: state
RELAYER = addr("0x5555555555555555555555555555555555555555")
OUTSIDER_KEY = int.from_bytes(k256(b"erc8350-client test key: outsider"), "big")

# v2 inputs that break more than one rule, so any refusal is correct for them.
# The rule each is named after is driven by a single-defect case instead.
MULTI_DEFECT = {
    "ZeroSpaceId": "a zero spaceId also fails the derivation check",
    "ZeroAddress": "its spaceId is derived from 0x2222..., so it also fails the derivation check",
    "UnknownSpace": "an unregistered Space has head zero, so sequence 6 also breaks the "
                    "sequence rule; which fires first is reference order",
}


def _expect_rejected(rep: Report, layer: str, name: str, reg: Registry, call, expect=None):
    """Run a call that must be refused and must leave the registry unchanged.
    With `expect`, the refusal must also come from that rule (a Rejected code),
    so a case cannot pass because an earlier check happened to fire."""
    before = reg.snapshot()
    try:
        call()
    except Rejected as exc:
        unchanged = reg.snapshot() == before
        right_rule = expect is None or exc.code == expect
        rep.check(layer, name, unchanged and right_rule,
                  f"rejected ({exc.code}: {exc.rule}); state "
                  f"{'unchanged' if unchanged else 'CHANGED'}"
                  + ("" if right_rule else f"; expected rule {expect}"))
        return exc
    except Unsupported as exc:
        rep.check(layer, name, False, f"unsupported path reached: {exc}")
        return None
    except Exception as exc:  # an implementation bug must be reported, not abort the run
        rep.check(layer, name, False, f"crashed: {exc!r}")
        return None
    rep.check(layer, name, False, "ACCEPTED an input the specification refuses")
    return None


def _transition_event(events: dict, d: Delta, tid: bytes, root: bytes, authorizer: bytes):
    return expected_event(events, "TransitionCommitted", spaceId=d.space_id,
                          transitionId=tid, sequence=d.sequence,
                          prevStateRoot=d.prev_state_root, nextStateRoot=root,
                          deltaCommitment=d.delta_commitment,
                          provenanceCommitment=d.provenance_commitment,
                          profileId=d.profile_id, locatorCommitment=d.locator_commitment,
                          authorizer=authorizer)


def run_state(rep: Report, v2: dict, registry_cls=None, events=None):
    registry_cls = registry_cls or Registry
    events = events or {}
    sp = v2["space"]
    dom = v2["eip712"]
    controller, authorizer = addr(sp["controller"]), addr(sp["authorizer"])
    sid = b32(sp["spaceId"])
    reg = registry_cls(int(dom["chainId"]), addr(dom["verifyingContract"]))
    rep.equal("state", "registry domainSeparator", reg.domain, b32(dom["domainSeparator"]))

    path = reg.register_space(controller, sid, controller, authorizer, b32(sp["salt"]))
    rep.check("state", "register v2 Space (controller, direct-empty)",
              reg.space_authorization(sid) == (controller, authorizer, 0)
              and reg.head(sid) == (ZERO32, ZERO32, 0), path)
    rep.check("state", "SpaceRegistered event",
              reg.events[-1:] == [expected_event(events, "SpaceRegistered", spaceId=sid,
                                                 controller=controller, authorizer=authorizer)])
    for entry in v2["chain"]:
        d, x = Delta.from_json(entry["delta"]), entry["expected"]
        try:
            tid, root, path = reg.commit_transition(authorizer, d)
        except (Rejected, Unsupported) as exc:
            rep.check("state", f"commit {entry['label']}", False, f"refused a valid delta: {exc}")
            continue
        rep.check("state", f"commit {entry['label']} (authorizer, {path})",
                  reg.head(sid) == (tid, root, d.sequence)
                  and (tid, root) == (b32(x["transitionId"]), b32(x["nextStateRoot"])),
                  f"head sequence {d.sequence}, root {hexs(root)}")
        rep.check("state", f"commit {entry['label']} TransitionCommitted event",
                  reg.events[-1:] == [_transition_event(events, d, tid, root, authorizer)])

    reject_names = {}
    for case in v2["rejections"]:
        name, target, inp = case["name"], case["target"], case["input"]
        base = case["signature"].split("(")[0]
        expect = None if base in MULTI_DEFECT else base
        label = f"refuse {name}"
        if target == "commitTransition":
            d = Delta.from_json(inp)
            if name.startswith("InvalidAuthorization"):
                digest = signing_digest(reg.domain, transition_id_of(d))
                if "wrong signer" in name:
                    sig, expect = ecdsa_sign(OUTSIDER_KEY, digest), "signer"
                    ok_shape = len(sig) == 65 and ecdsa_recover(digest, sig) not in (None, authorizer)
                    rep.check("state", f"{name}: signature is canonical, recovers elsewhere",
                              ok_shape, hexs(address_of(OUTSIDER_KEY)))
                else:
                    # Nobody holds the v2 authorizer's key, so any 64 bytes would also
                    # fail recovery; requiring the length rule is what makes this bite.
                    sig, expect = ecdsa_sign(OUTSIDER_KEY, digest)[:64], "length"
                call = (lambda d=d, sig=sig: reg.commit_transition(RELAYER, d, sig))
                # Control: the same delta is accepted when the authorizer submits it,
                # so the refusal below is the signature's alone.
                trial = copy.deepcopy(reg)
                try:
                    tid, _, _ = trial.commit_transition(authorizer, d)
                    control, detail = trial.head(sid)[0] == tid, ""
                except (Rejected, Unsupported) as exc:
                    control, detail = False, f"control refused: {exc}"
                rep.check("state", f"{name}: control, same delta accepted from the authorizer",
                          control, detail)
            else:
                call = (lambda d=d: reg.commit_transition(authorizer, d))
        elif target == "registerSpace":
            c = addr(inp["controller"])
            call = (lambda inp=inp, c=c: reg.register_space(
                c, inp["spaceId"], c, inp["authorizer"], b32(inp["salt"])))
            if "precondition" in case:
                rep.check("state", f"{name}: precondition holds (Space registered)",
                          b32(inp["spaceId"]) in reg.spaces)
        else:
            rep.check("state", f"{name}: unknown target {target}", False)
            continue
        if base in MULTI_DEFECT:
            label += f" (any rule: {MULTI_DEFECT[base]})"
        reject_names[name] = (case, _expect_rejected(rep, "state", label, reg, call, expect))
    rep.check("state", "12 rejection cases exercised", len(reject_names) == 12,
              str(len(reject_names)))

    # Single-defect cases for the rules the multi-defect vectors only touch.
    fresh = k256(b"erc8350-client single-defect salt")
    zero_sid = space_id_of(ZERO20, fresh)
    _expect_rejected(rep, "state", "refuse zero controller at registration (spaceId "
                     "re-derives from it)", reg,
                     lambda: reg.register_space(ZERO20, zero_sid, ZERO20, authorizer, fresh),
                     "ZeroAddress")
    own_sid = space_id_of(controller, fresh)
    _expect_rejected(rep, "state", "refuse zero authorizer at registration (spaceId "
                     "re-derives)", reg,
                     lambda: reg.register_space(controller, own_sid, controller, ZERO20, fresh),
                     "ZeroAddress")
    # A well-formed genesis delta into a Space nobody registered: only the
    # missing registration can refuse it, so a registry that creates Spaces on
    # first commit fails here.
    ghost = Delta(own_sid, 1, ZERO32, k256(b"ghost delta"), ZERO32,
                  k256(b"erc8350-client test profile"), ZERO32)
    _expect_rejected(rep, "state", "refuse a genesis commit into an unregistered Space", reg,
                     lambda: reg.commit_transition(authorizer, ghost))
    rep.check("state", "head after all rejections is the chain head",
              reg.head(sid)[1:] == (b32(v2["chain"][-1]["expected"]["nextStateRoot"]), 5))

    for name, (case, exc) in reject_names.items():
        if exc is None:
            rep.check("compat", f"{name}", False, "not rejected")
            continue
        want_name = case["signature"].split("(")[0]
        rep.check("compat", f"{name}: error name", exc.name == want_name,
                  f"{exc.name} vs {want_name}")
        rep.check("compat", f"{name}: ABI selector",
                  hexs(k256(exc.abi_signature.encode())[:4]) == case["selector"]
                  and exc.abi_signature == case["signature"],
                  f"{exc.abi_signature} -> {hexs(k256(exc.abi_signature.encode())[:4])}")
        if "expectedArgs" in case:
            want = tuple(case["expectedArgs"][k] for k in ("expected", "received"))
            got = tuple(hexs(v) if isinstance(v, bytes) else str(v) for v in exc.values)
            rep.check("compat", f"{name}: error arguments", got == want, str(got))


# --------------------------------------------------------------- layer: ecdsa
KEY_LABELS = ("controller", "authorizer", "outsider", "controller-2")
ECDSA_CHAIN_ID = 11155111
ECDSA_REGISTRY = addr("0x8350835083508350835083508350835083508350")
SECOND_DEPLOYMENT = (1, addr("0x4444444444444444444444444444444444444444"))

# Known answers produced outside this file, so the ecdsa layer cannot pass on
# self-consistency alone: the address of private key 1, and `cast wallet
# address` / `cast wallet sign --no-hash` (Foundry 1.8.3) for one test key.
KNOWN_KEY1_ADDRESS = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
KNOWN_AUTHORIZER_ADDRESS = "0xdb5d1893c97fd4f887c52dacac7c858caa7604dd"
KNOWN_CAST_PREIMAGE = b"cross-check authorizer 0"
KNOWN_CAST_SIGNATURE = (
    "0xac80cb280cbf968c86dcd75a1a24f04fcc2b2f4975ff6ec85b7d719d8eaf240c"
    "58094169ba4d91afd6e3e5878e94d9c14363cbf5279d19a6015934acf177c77d1b")


def _test_key(label: str) -> int:
    return int.from_bytes(k256(f"erc8350-client test key: {label}".encode()), "big")


def _delta_args(d: Delta) -> dict:
    return {"spaceId": hexs(d.space_id), "sequence": str(d.sequence),
            "prevStateRoot": hexs(d.prev_state_root), "deltaCommitment": hexs(d.delta_commitment),
            "provenanceCommitment": hexs(d.provenance_commitment),
            "profileId": hexs(d.profile_id), "locatorCommitment": hexs(d.locator_commitment)}


def run_ecdsa(rep: Report, vectors: list, registry_cls=None, events=None):
    """EOA authorization for all three operations with this file's public test
    keys. It runs on a chain and registry other than the v2 vectors', signs
    with domains computed here rather than read from the registry under test,
    and repeats a signed registration on a second deployment, so a registry
    whose domain ignores its chain or address fails. Every refusal must come
    from the rule the case names. Passing cases are recorded as static vectors,
    with their call arguments."""
    registry_cls = registry_cls or Registry
    events = events or {}

    # Known answers first: without them every signature below could be wrong
    # in the same way on both sides and still agree.
    rep.check("ecdsa", "known answer: address of private key 1",
              hexs(address_of(1)) == KNOWN_KEY1_ADDRESS, hexs(address_of(1)))
    rep.check("ecdsa", "known answer: test key address equals cast's",
              hexs(address_of(_test_key("authorizer"))) == KNOWN_AUTHORIZER_ADDRESS)
    cast_digest = k256(KNOWN_CAST_PREIMAGE)
    rep.check("ecdsa", "known answer: signature byte-equal to cast's",
              hexs(ecdsa_sign(_test_key("authorizer"), cast_digest)) == KNOWN_CAST_SIGNATURE)
    rep.check("ecdsa", "known answer: cast's signature recovers cast's address",
              hexs(ecdsa_recover(cast_digest, bytes.fromhex(KNOWN_CAST_SIGNATURE[2:]))
                   or b"") == KNOWN_AUTHORIZER_ADDRESS)

    chain_id, registry = ECDSA_CHAIN_ID, ECDSA_REGISTRY
    domain = domain_separator(chain_id, registry)
    other_chain = domain_separator(1, registry)
    other_registry = domain_separator(chain_id, addr("0x8350835083508350835083508350835083508351"))
    keys = {name: _test_key(name) for name in KEY_LABELS}
    who = {name: address_of(k) for name, k in keys.items()}
    reg = registry_cls(chain_id, registry)
    salt = k256(b"erc8350-client test space")
    sid = space_id_of(who["controller"], salt)
    profile = k256(b"erc8350-client test profile")

    def sign(key, struct_hash, dom=None):
        return ecdsa_sign(keys[key], signing_digest(dom or domain, struct_hash))

    def attempt(case, op, call, *, sender, required, struct_hash, expect, args, sig=b"",
                signer=None, signed_hash=None, signed_domain=None, defect=None,
                path="ecdsa", event=None, on=None, on_domain=None, on_chain=None):
        """expect is "accept" or the Rejected code the refusal must carry."""
        target = on or reg
        if expect == "accept":
            try:
                got = call()
            except Exception as exc:
                rep.check("ecdsa", case, False, f"refused: {exc!r}")
                return
            got_path = got[2] if isinstance(got, tuple) else got
            event_ok = event is None or target.events[-1:] == [event]
            if not rep.check("ecdsa", case, got_path == path and event_ok,
                             f"accepted via {got_path}" + ("" if event_ok else "; event mismatch")):
                return
            outcome = "accept"
        else:
            exc = _expect_rejected(rep, "ecdsa", case, target, call, expect)
            if exc is None or exc.code != expect:
                return
            outcome = f"reject: {exc.rule}"
        dom = on_domain or domain
        signer_hex = None if signer is None else hexs(who[signer] if isinstance(signer, str) else signer)
        entry = {
            "case": case, "operation": op, "chainId": str(on_chain or chain_id),
            "verifyingContract": hexs(target.address), "sender": hexs(sender), "call": args,
            "requiredAccount": hexs(required), "structHash": hexs(struct_hash),
            "signingDigest": hexs(signing_digest(dom, struct_hash)),
            "signature": hexs(sig), "signer": signer_hex, "expected": outcome}
        if signed_hash is not None or signed_domain is not None:
            entry["signedDigest"] = hexs(signing_digest(signed_domain or dom,
                                                        signed_hash or struct_hash))
        if expect != "accept":
            entry["refusedBy"] = expect
        if defect:
            entry["defect"] = defect
        vectors.append(entry)

    # ---- registerSpace: only the controller authorizes, and the authorizer it
    # names is bound by that authorization, so a front-runner who learns the
    # salt cannot install their own.
    def reg_args(authorizer):
        return {"spaceId": hexs(sid), "controller": hexs(who["controller"]),
                "authorizer": hexs(who[authorizer]), "salt": hexs(salt)}

    def register(sig, authorizer="authorizer", sender=RELAYER, on=None):
        target = on or reg
        return lambda: target.register_space(sender, sid, who["controller"], who[authorizer],
                                             salt, sig)

    reg_hash = registration_hash(sid, who["controller"], who["authorizer"])
    r_ctl = sign("controller", reg_hash)
    k = dict(op="registerSpace", required=who["controller"], struct_hash=reg_hash,
             args=reg_args("authorizer"))
    attempt("register relayed with an empty signature", call=register(b""),
            sender=RELAYER, expect="length", **k)
    attempt("register by direct call from the named authorizer, not the controller",
            call=register(b"", sender=who["authorizer"]), sender=who["authorizer"],
            expect="length", **k)
    bad_self = sign("outsider", reg_hash)
    attempt("register self-call by the controller with an outsider's bytes",
            call=register(bad_self, sender=who["controller"]), sender=who["controller"],
            expect="signer", sig=bad_self, signer="outsider", **k)
    attempt("register signed by an outsider", call=register(sign("outsider", reg_hash)),
            sender=RELAYER, expect="signer", sig=sign("outsider", reg_hash),
            signer="outsider", **k)
    attempt("register signed by the authorizer, not the controller",
            call=register(sign("authorizer", reg_hash)), sender=RELAYER, expect="signer",
            sig=sign("authorizer", reg_hash), signer="authorizer", **k)
    attempt("register front-run: the controller's signature with another authorizer",
            "registerSpace", register(r_ctl, authorizer="outsider"), sender=RELAYER,
            required=who["controller"],
            struct_hash=registration_hash(sid, who["controller"], who["outsider"]),
            expect="signer", args=reg_args("outsider"), sig=r_ctl, signer="controller",
            signed_hash=reg_hash)
    r_other = sign("controller", reg_hash, other_chain)
    attempt("register signed for another chain", call=register(r_other), sender=RELAYER,
            expect="signer", sig=r_other, signer="controller", signed_domain=other_chain, **k)
    attempt("register relayed with the controller's signature", call=register(r_ctl),
            sender=RELAYER, expect="accept", sig=r_ctl, signer="controller",
            event=expected_event(events, "SpaceRegistered", spaceId=sid,
                                 controller=who["controller"], authorizer=who["authorizer"]),
            **k)
    attempt("register replayed", call=register(r_ctl), sender=RELAYER,
            expect="SpaceAlreadyRegistered", sig=r_ctl, signer="controller", **k)

    # The same Space on a second deployment: a signature binds one registry on
    # one chain, and the registry must check against its own domain.
    b_chain, b_addr = SECOND_DEPLOYMENT
    reg_b = registry_cls(b_chain, b_addr)
    dom_b = domain_separator(b_chain, b_addr)
    kb = dict(k, on=reg_b, on_domain=dom_b, on_chain=b_chain)
    attempt("second deployment refuses the first deployment's registration signature",
            call=register(r_ctl, on=reg_b), sender=RELAYER, expect="signer", sig=r_ctl,
            signer="controller", signed_domain=domain, **kb)
    r_b = sign("controller", reg_hash, dom_b)
    attempt("second deployment accepts a registration signed for it",
            call=register(r_b, on=reg_b), sender=RELAYER, expect="accept", sig=r_b,
            signer="controller",
            event=expected_event(events, "SpaceRegistered", spaceId=sid,
                                 controller=who["controller"], authorizer=who["authorizer"]),
            **kb)

    # ---- commitTransition: only the authorizer approves transitions.
    def delta(seq, prev, space=sid, label=None):
        return Delta(space, seq, prev, k256((label or f"delta {seq}").encode()), ZERO32,
                     profile, ZERO32)

    def commit(d, sig, sender=RELAYER):
        return lambda: reg.commit_transition(sender, d, sig)

    def committed(d, tid, root, authorizer):
        return _transition_event(events, d, tid, root, authorizer)

    d1 = delta(1, ZERO32)
    t1 = transition_id_of(d1)
    root1 = next_state_root_of(ZERO32, t1)
    c1 = dict(op="commitTransition", required=who["authorizer"], struct_hash=t1,
              args=_delta_args(d1))
    attempt("commit #1 signed by the controller, not the authorizer",
            call=commit(d1, sign("controller", t1)), sender=RELAYER, expect="signer",
            sig=sign("controller", t1), signer="controller", **c1)
    attempt("commit #1 direct call by the controller, not the authorizer",
            call=commit(d1, b"", sender=who["controller"]), sender=who["controller"],
            expect="length", **c1)
    s1 = sign("authorizer", t1)
    attempt("commit #1 relayed with the authorizer's signature", call=commit(d1, s1),
            sender=RELAYER, expect="accept", sig=s1, signer="authorizer",
            event=committed(d1, t1, root1, who["authorizer"]), **c1)

    d2 = delta(2, root1)
    t2 = transition_id_of(d2)
    root2 = next_state_root_of(root1, t2)
    good = sign("authorizer", t2)
    r, s, v = _split(good)
    high_s = malleate(good)
    rep.check("ecdsa", "high-s twin keeps v in {27, 28} and recovers the same key "
              "without the low-s rule",
              high_s[64] in (27, 28) and _split(high_s)[1] > HALF_N
              and _recover_unchecked(signing_digest(domain, t2), high_s) == who["authorizer"])
    tail = good[64:]
    bad = [
        ("commit #2 signed by an outsider", sign("outsider", t2), RELAYER, "signer",
         "outsider", None, None),
        ("commit #2 high-s (malleated) signature", high_s, RELAYER, "noncanonical",
         "authorizer", None, "high-s"),
        (f"commit #2 v = {v - 27} instead of {v}", good[:64] + bytes([v - 27]), RELAYER,
         "noncanonical", "authorizer", None, "v not 27/28"),
        ("commit #2 r = 0 (x = 0 is not on the curve, so recovery refuses it either way)",
         b"\x00" * 32 + good[32:], RELAYER, "noncanonical", None, None, "r = 0"),
        ("commit #2 s = 0", good[:32] + b"\x00" * 32 + tail, RELAYER, "noncanonical", None,
         None, "s = 0"),
        ("commit #2 r = n", N.to_bytes(32, "big") + good[32:], RELAYER, "noncanonical", None,
         None, "r = n"),
        ("commit #2 s = n", good[:32] + N.to_bytes(32, "big") + tail, RELAYER, "noncanonical",
         None, None, "s = n"),
        ("commit #2 compact 64-byte (EIP-2098) encoding",
         good[:32] + (s | (v - 27) << 255).to_bytes(32, "big"), RELAYER, "length",
         "authorizer", None, "64 bytes"),
        ("commit #2 66-byte padded signature", good + b"\x00", RELAYER, "length", "authorizer",
         None, "66 bytes"),
        ("commit #2 empty signature from a relayer", b"", RELAYER, "length", None, None, None),
        ("commit #2 self-call with an outsider's bytes", sign("outsider", t2),
         who["authorizer"], "signer", "outsider", None, None),
        ("commit #2 signature for another chain", sign("authorizer", t2, other_chain), RELAYER,
         "signer", "authorizer", other_chain, None),
        ("commit #2 signature for another registry", sign("authorizer", t2, other_registry),
         RELAYER, "signer", "authorizer", other_registry, None),
    ]
    c2 = dict(op="commitTransition", required=who["authorizer"], struct_hash=t2,
              args=_delta_args(d2))
    for case, sig, sender, code, signer, signed_domain, defect in bad:
        attempt(case, call=commit(d2, sig, sender), sender=sender, expect=code, sig=sig,
                signer=signer, signed_domain=signed_domain, defect=defect, **c2)
    attempt("commit #2 relayed with the canonical signature", call=commit(d2, good),
            sender=RELAYER, expect="accept", sig=good, signer="authorizer",
            event=committed(d2, t2, root2, who["authorizer"]), **c2)

    # ---- updateSpaceAuthorization: the current controller authorizes, the
    # nonce stops a replay by that same controller, both replacements take
    # effect, and a rotated-out controller loses authority.
    def rotate(new_c, new_a, sig, sender=RELAYER):
        return lambda: reg.update_space_authorization(sender, sid, who.get(new_c, ZERO20),
                                                      who.get(new_a, ZERO20), sig)

    def rot_args(new_c, new_a):
        return {"spaceId": hexs(sid), "newController": hexs(who.get(new_c, ZERO20)),
                "newAuthorizer": hexs(who.get(new_a, ZERO20))}

    def updated(new_c, new_a, nonce):
        return expected_event(events, "SpaceAuthorizationUpdated", spaceId=sid,
                              controller=who[new_c], authorizer=who[new_a], configNonce=nonce)

    rot1 = authorization_hash(sid, who["controller"], who["outsider"], 1)
    k1 = dict(op="updateSpaceAuthorization", required=who["controller"], struct_hash=rot1,
              args=rot_args("controller", "outsider"))
    attempt("rotation 1 relayed with an empty signature",
            call=rotate("controller", "outsider", b""), sender=RELAYER, expect="length", **k1)
    attempt("rotation 1 by direct call from the authorizer, not the controller",
            call=rotate("controller", "outsider", b"", sender=who["authorizer"]),
            sender=who["authorizer"], expect="length", **k1)
    by_auth = sign("authorizer", rot1)
    attempt("rotation 1 signed by the authorizer, not the controller",
            call=rotate("controller", "outsider", by_auth), sender=RELAYER, expect="signer",
            sig=by_auth, signer="authorizer", **k1)
    bad_self = sign("outsider", rot1)
    attempt("rotation 1 self-call by the controller with an outsider's bytes",
            call=rotate("controller", "outsider", bad_self, sender=who["controller"]),
            sender=who["controller"], expect="signer", sig=bad_self, signer="outsider", **k1)
    for case, new_c, new_a in (("rotation to a zero controller", None, "outsider"),
                               ("rotation to a zero authorizer", "controller", None)):
        zh = authorization_hash(sid, who.get(new_c, ZERO20), who.get(new_a, ZERO20), 1)
        zs = sign("controller", zh)
        attempt(case, "updateSpaceAuthorization", rotate(new_c, new_a, zs), sender=RELAYER,
                required=who["controller"], struct_hash=zh, expect="ZeroAddress",
                args=rot_args(new_c, new_a), sig=zs, signer="controller")
    rot1_sig = sign("controller", rot1)
    attempt("rotation 1 relayed with the controller's signature",
            call=rotate("controller", "outsider", rot1_sig), sender=RELAYER, expect="accept",
            sig=rot1_sig, signer="controller", event=updated("controller", "outsider", 1), **k1)
    rep.check("ecdsa", "rotation 1 replaced the authorizer",
              sid in reg.spaces and
              reg.space_authorization(sid) == (who["controller"], who["outsider"], 1))
    # The same controller is still in charge, so only the nonce can refuse this.
    attempt("rotation 1 replayed by the same controller (nonce is now 2)",
            "updateSpaceAuthorization", rotate("controller", "outsider", rot1_sig),
            sender=RELAYER, required=who["controller"],
            struct_hash=authorization_hash(sid, who["controller"], who["outsider"], 2),
            expect="signer", args=rot_args("controller", "outsider"), sig=rot1_sig,
            signer="controller", signed_hash=rot1)

    rot2 = authorization_hash(sid, who["controller-2"], who["outsider"], 2)
    k2 = dict(op="updateSpaceAuthorization", required=who["controller"], struct_hash=rot2,
              args=rot_args("controller-2", "outsider"))
    attempt("rotation 2 by direct call from the proposed new controller",
            call=rotate("controller-2", "outsider", b"", sender=who["controller-2"]),
            sender=who["controller-2"], expect="length", **k2)
    rot2_sig = sign("controller", rot2)
    attempt("rotation 2 relayed with the controller's signature",
            call=rotate("controller-2", "outsider", rot2_sig), sender=RELAYER,
            expect="accept", sig=rot2_sig, signer="controller",
            event=updated("controller-2", "outsider", 2), **k2)
    rep.check("ecdsa", "rotation 2 replaced the controller",
              sid in reg.spaces and
              reg.space_authorization(sid) == (who["controller-2"], who["outsider"], 2))
    rot3 = authorization_hash(sid, who["controller-2"], who["outsider"], 3)
    k3 = dict(op="updateSpaceAuthorization", required=who["controller-2"], struct_hash=rot3,
              args=rot_args("controller-2", "outsider"))
    old_ctl = sign("controller", rot3)
    attempt("rotation 3 signed by the rotated-out controller",
            call=rotate("controller-2", "outsider", old_ctl), sender=RELAYER,
            expect="signer", sig=old_ctl, signer="controller", **k3)
    attempt("rotation 3 by direct call from the new controller",
            call=rotate("controller-2", "outsider", b"", sender=who["controller-2"]),
            sender=who["controller-2"], expect="accept", path="direct-empty",
            event=updated("controller-2", "outsider", 3), **k3)

    d3 = delta(3, root2)
    t3 = transition_id_of(d3)
    root3 = next_state_root_of(root2, t3)
    c3 = dict(op="commitTransition", required=who["outsider"], struct_hash=t3,
              args=_delta_args(d3))
    old_auth = sign("authorizer", t3)
    attempt("commit #3 by the rotated-out authorizer", call=commit(d3, old_auth),
            sender=RELAYER, expect="signer", sig=old_auth, signer="authorizer", **c3)
    new_auth = sign("outsider", t3)
    attempt("commit #3 relayed with the new authorizer's signature",
            call=commit(d3, new_auth), sender=RELAYER, expect="accept", sig=new_auth,
            signer="outsider", event=committed(d3, t3, root3, who["outsider"]), **c3)
    d4 = delta(4, root3)
    t4 = transition_id_of(d4)
    attempt("commit #4 by direct call from the new authorizer", "commitTransition",
            commit(d4, b"", sender=who["outsider"]), sender=who["outsider"],
            required=who["outsider"], struct_hash=t4, expect="accept", path="direct-empty",
            args=_delta_args(d4),
            event=committed(d4, t4, next_state_root_of(root3, t4), who["outsider"]))

    # ---- Exact ECDSA boundaries. For a chosen (r, s) pair the recovered
    # address is fixed by the digest alone, so a Space whose authorizer IS that
    # address makes the signature the only thing in question. Recovery for
    # these synthetic signers uses no private key; `signer` holds the address.
    def boundary_space(label, r_val, s_val):
        b_salt = k256(f"erc8350-client boundary: {label}".encode())
        b_sid = space_id_of(who["controller"], b_salt)
        bd = delta(1, ZERO32, space=b_sid, label=f"boundary {label}")
        b_tid = transition_id_of(bd)
        signer = _recover_raw(signing_digest(domain, b_tid), r_val, s_val, 0)
        bh = registration_hash(b_sid, who["controller"], signer)
        reg.register_space(RELAYER, b_sid, who["controller"], signer, b_salt,
                           sign("controller", bh))
        return bd, b_tid, signer

    # s exactly n/2 is canonical; its twin n - n/2 = n/2 + 1 is the first value over.
    bd, b_tid, a_s = boundary_space("low-s", r, HALF_N)
    at_bound = r.to_bytes(32, "big") + HALF_N.to_bytes(32, "big") + bytes([27])
    over = r.to_bytes(32, "big") + (HALF_N + 1).to_bytes(32, "big") + bytes([28])
    rep.check("ecdsa", "s = n/2 + 1 is the malleated twin of s = n/2 (same signer without "
              "the low-s rule)",
              _recover_unchecked(signing_digest(domain, b_tid), over) == a_s)
    kb_s = dict(op="commitTransition", required=a_s, struct_hash=b_tid, args=_delta_args(bd))
    attempt("commit with s = n/2 + 1, one over the low-s bound", call=commit(bd, over),
            sender=RELAYER, expect="noncanonical", sig=over, signer=a_s,
            defect="s = n/2 + 1", **kb_s)
    attempt("commit with s = n/2 exactly (the bound is inclusive)", call=commit(bd, at_bound),
            sender=RELAYER, expect="accept", sig=at_bound, signer=a_s,
            event=committed(bd, b_tid, next_state_root_of(ZERO32, b_tid), a_s), **kb_s)

    # r >= n with x = r a valid curve point: a registry without the r < n rule
    # recovers exactly this Space's authorizer from it.
    r_big = next(x for x in range(N + 1, P) if pow((x ** 3 + 7) % P, (P - 1) // 2, P) == 1)
    bd, b_tid, a_r = boundary_space("r >= n", r_big, HALF_N // 3)
    sig_big = r_big.to_bytes(32, "big") + (HALF_N // 3).to_bytes(32, "big") + bytes([27])
    attempt(f"commit with r = n + {r_big - N} (on the curve, at or above n)",
            call=commit(bd, sig_big), sender=RELAYER, expect="noncanonical", sig=sig_big,
            signer=a_r, defect="r >= n", op="commitTransition", required=a_r,
            struct_hash=b_tid, args=_delta_args(bd))

    # Declared boundary: an account with code is not guessed at.
    coded = registry_cls(chain_id, registry, code={who["authorizer"]: b"\xef\x01\x00" + b"\x11" * 20})
    coded.register_space(who["controller"], sid, who["controller"], who["authorizer"], salt)
    before = coded.snapshot()
    try:
        coded.commit_transition(RELAYER, d1, s1)
        outcome = "accepted"
    except Unsupported:
        outcome = "unsupported"
    except Rejected:
        outcome = "rejected"
    rep.check("ecdsa", "authorizer with code is declared unsupported, state unchanged",
              outcome == "unsupported" and coded.snapshot() == before, outcome)


def _recover_unchecked(digest: bytes, signature: bytes):
    """Recovery without the low-s rule; used only to show a malleated
    signature is otherwise valid, so its refusal is the canonical-s rule."""
    r, s, v = _split(signature)
    if len(signature) != 65 or v not in (27, 28) or not 0 < r < N or not 0 < s < N:
        return None
    return _recover_raw(digest, r, s, v - 27)


# ------------------------------------------------------------------------ main
def _source_identity():
    here = Path(__file__).resolve()
    ident = {"file": here.name, "sha256": hashlib.sha256(here.read_bytes()).hexdigest()}
    try:
        def git(*args):
            return subprocess.run(["git", *args], cwd=here.parent, capture_output=True,
                                  text=True)
        top = git("rev-parse", "HEAD")
        if top.returncode != 0:
            raise OSError("not a git checkout")
        # "untracked" (including ignored) means the commit does not contain this
        # file at all; only a tracked file can be "clean" against it.
        if git("ls-files", "--error-unmatch", "--", here.name).returncode != 0:
            state = "untracked"
        elif git("diff", "--quiet", "HEAD", "--", here.name).returncode != 0:
            state = "modified"
        else:
            state = "clean"
        ident.update(commit=top.stdout.strip(), fileState=state)
    except (OSError, subprocess.CalledProcessError):
        ident.update(commit=None, fileState=None)
    return ident


def run_all(raw: dict, signature_vectors: list = None, registry_cls=None) -> Report:
    v1 = json.loads(raw["v1.json"])
    v2 = json.loads(raw["v2.json"])
    fx = json.loads(raw["sepolia-fixture-v1.json"])
    draft = raw["erc-8350.md"].decode("utf-8")
    events = draft_events(draft)
    rep = Report()
    vectors = signature_vectors if signature_vectors is not None else []
    for layer, run in (
            ("spec", lambda: run_spec(rep, draft, v1, v2)),
            ("hash", lambda: run_hash(rep, v1, v2)),
            ("fixture", lambda: run_fixture(rep, v2, fx)),
            ("state", lambda: run_state(rep, v2, registry_cls, events)),
            ("ecdsa", lambda: run_ecdsa(rep, vectors, registry_cls, events))):
        try:
            run()
        except Exception as exc:  # a crash is a FAIL with a reason, never a silent stop
            rep.check(layer, "layer ran to completion", False, f"crashed: {exc!r}")
    return rep


def signature_vector_file(rep: Report, vectors: list) -> dict:
    """The static ECDSA vectors, only from a run in which every layer passed."""
    if not all(rep.passed(layer) for layer in LAYERS):
        raise RuntimeError("signature vectors not written: the run did not pass")
    return {
        "schema": "erc8350-client/signature-vectors/v1",
        "source": _source_identity(),
        "keys": {name: {"derivation": f'keccak256("erc8350-client test key: {name}")',
                        "privateKey": hexs(_test_key(name).to_bytes(32, "big")),
                        "address": hexs(address_of(_test_key(name)))}
                 for name in KEY_LABELS},
        "warning": "public test-only keys; never use them for funds or authority",
        "sequence": (
            f"Cases run in order against one registry (chainId {ECDSA_CHAIN_ID}, "
            f"verifyingContract {hexs(ECDSA_REGISTRY)}); each sees the state the accepted "
            "cases before it left. Space salt = keccak256(\"erc8350-client test space\"); "
            "controller and authorizer keys as above. Delta n: deltaCommitment = "
            "keccak256(\"delta n\"), profileId = keccak256(\"erc8350-client test profile\"), "
            "provenance and locator zero. Rotation 1 moves the Space to controller-2 with "
            "the outsider key as authorizer; rotation 2 repeats that by direct call."),
        "fields": ("call holds the operation's arguments. signingDigest is the digest the "
                   "registry checks once the call reaches signature validation; cases "
                   "refused by a state rule (ZeroAddress, SpaceAlreadyRegistered) never "
                   "reach it. signedDigest, when present, is what was actually signed. "
                   "signer is the key that signed, null for an empty or synthetic "
                   "signature. refusedBy is the rule that must refuse the case: length, "
                   "noncanonical, signer, or a state rule name."),
        "cases": vectors,
    }


def main():
    ap = argparse.ArgumentParser(description="Independent ERC-8350 client and conformance run")
    ap.add_argument("--inputs", default=None,
                    help="directory holding the pinned input files (default: fetch them)")
    ap.add_argument("--json", default=None, help="write the result record here")
    ap.add_argument("--emit-signature-vectors", default=None,
                    help="write the ecdsa cases as static vectors here")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every check")
    args = ap.parse_args()

    raw = load_inputs(args.inputs)
    sig_vectors = []
    rep = run_all(raw, sig_vectors)

    print("ERC-8350 independent client")
    print(f"  Draft   ethereum/ERCs@{DRAFT_COMMIT[:12]}  erc-8350.md")
    print(f"  vectors AwareLiquid/AgentMemoryState@{VECTORS_COMMIT[:12]}")
    for name, (_, digest) in INPUTS.items():
        print(f"    {name:26} sha256 {digest}")
    print()
    all_ok = True
    for layer in LAYERS:
        checks = rep.checks[layer]
        ok = rep.passed(layer)
        all_ok &= ok
        failed = [c for c in checks if not c["pass"]]
        note = "  (reference compatibility, not normative)" if layer == "compat" else ""
        print(f"  {layer:8} {'PASS' if ok else 'FAIL'}  {len(checks) - len(failed)}/{len(checks)}{note}")
        for c in (checks if args.verbose else failed):
            mark = "ok  " if c["pass"] else "FAIL"
            print(f"      {mark} {c['check']}" + (f"  [{c['detail']}]" if c["detail"] else ""))
    print()
    print("RESULT:", "ALL LAYERS PASS" if all_ok else "FAILURES PRESENT")

    if args.json:
        record = {
            "schema": "erc8350-client/result/v1",
            "source": _source_identity(),
            "specBaseline": {
                "draft": {"repository": "ethereum/ERCs", "commit": DRAFT_COMMIT,
                          "path": "ERCS/erc-8350.md",
                          "sha256": INPUTS["erc-8350.md"][1]},
                "vectors": {"repository": "AwareLiquid/AgentMemoryState",
                            "commit": VECTORS_COMMIT,
                            "files": {k: v[1] for k, v in INPUTS.items() if k != "erc-8350.md"}},
                "proposals": "ERC-1271 is not implemented, so AQ-01 and AQ-03 do not arise. "
                             "Required accounts per operation and validation of non-empty "
                             "bytes from the required account follow the A-02 reading of "
                             "the reference's decision table.",
            },
            "toolchain": {"python": platform.python_version(),
                          "pycryptodome": Crypto.__version__},
            "commands": ["pip install pycryptodome==3.23.0",
                         "python3 recompute/erc8350_client.py --json result.json",
                         "python3 recompute/erc8350_client.py --inputs DIR --json result.json"
                         "  # offline; the same sha256 pins are enforced"],
            "supportedCapabilities": {"directEmpty": "enabled for all three operations",
                                      "ecdsa": "65-byte canonical low-s, v in {27,28}",
                                      "erc1271": "not supported (accounts modelled without code)"},
            "layers": {layer: {"result": "PASS" if rep.passed(layer) else "FAIL",
                               "checks": rep.checks[layer]} for layer in LAYERS},
            "limitations": [
                "no ERC-1271, Safe or EIP-7702 delegated-account authorization",
                "no deployed-code identity or immutability evidence",
                "no gas or liveness modelling",
                "TransitionAlreadyExists guarded but unreachable, as the vectors note",
                "the v2 authorizer has no published key, so v2's two authorization "
                "rejections use an outsider key and rely on this client's rule codes; "
                "the ecdsa layer covers the same rules with keys whose holder is known",
                "v2's ZeroSpaceId and ZeroAddress inputs also fail spaceId derivation, so "
                "any refusal counts for them; single-defect cases cover ZeroAddress",
                "rule codes and events are this client's in-memory model; a deployed "
                "registry's errors and logs are compared only through the compat layer "
                "and erc8350_sepolia.py",
            ],
        }
        Path(args.json).write_text(json.dumps(record, indent=2) + "\n")
        print(f"result record: {args.json}")
    if args.emit_signature_vectors:
        try:
            body = signature_vector_file(rep, sig_vectors)
        except RuntimeError as exc:
            print(exc)
        else:
            Path(args.emit_signature_vectors).write_text(json.dumps(body, indent=2) + "\n")
            print(f"signature vectors: {args.emit_signature_vectors}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
