#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""
Recompute the ERC-8350 sequenced-transition rule from public chain data.

WHAT THIS PROVES

  Given a registry address and an RPC endpoint, for every Memory Space:

    1. every transitionId recomputes from the EIP-712 type string;
    2. every nextStateRoot recomputes as
       keccak(MEMORY_STATE_TYPEHASH, prevStateRoot, transitionId);
    3. the chain is gapless: sequence == prev + 1, and
       prevStateRoot == the prior transition's nextStateRoot, from sequence 1
       with prevStateRoot == 0;
    4. the head materialized in contract STORAGE — all three fields the spec's
       head() exposes: transitionId, stateRoot, sequence — equals the head
       recomputed by replaying the event path.

  (4) is the point. (1)-(3) check the itemized path; (4) checks that the slots
  anyone would read as "current state" are exactly the sum of that path. A
  registry whose stored head disagreed with its own emitted history would pass
  a golden-vector test and fail here.

THE TRUST BOUNDARY, STATED EXACTLY

  Storage is read by walking the Merkle-Patricia trie: the account proof is
  walked from the block's state root to obtain the storage root, then each
  requested slot is walked from that storage root. The walk requests specific
  slots and verifies those slots; the `value` and `storageHash` fields
  eth_getProof reports are asserted against the independently walked results
  and are otherwise unused. GIVEN the block's state root, this removes trust
  in the registry's view functions and in the proof-serving endpoint.

  The state root itself, and the event set, still come from the endpoint. To
  make that checkable rather than trusted, the script reconstructs the block
  header, verifies keccak(rlp(header)) equals the block hash, and PRINTS that
  hash: check it against any explorer or second endpoint (--cross-check-rpc
  automates this). Once the block hash is confirmed elsewhere, a fabricated
  state root fails the header check, a fabricated storage proof fails the
  walk, and a fabricated event history cannot land on the proven head without
  a keccak collision. What remains unprovable from one endpoint is omission:
  an endpoint can hide a whole Memory Space by filtering its logs. Cross-check
  against a second log source if that matters to you.

USAGE

    pip install pycryptodome
    python3 erc8350_sepolia.py                      # Sepolia defaults
    python3 erc8350_sepolia.py --rpc-url URL --registry 0x... --block N
    python3 erc8350_sepolia.py --cross-check-rpc URL2

  Exit 0 only when at least one Space was found and every Space verified.
  Anything else — mismatch, no transitions, unsupported proof shape — is
  nonzero. Needs an endpoint that serves eth_getLogs over the full range and
  eth_getProof at the chosen block.

  The observation block is an observation point, not part of the claim. Most
  endpoints serve eth_getProof only within a recent window, so --block with an
  old height will be refused; run without it to observe at the current head.
  While no new transitions land, every later block yields the same head, so
  the result reproduces even though the block number will not.

LIMITATIONS, STATED PLAINLY

  * The trie walker is minimal. It handles branch, extension and leaf nodes
    referenced by hash, validates hex-prefix flags and padding, and RAISES on
    anything else — including inlined (<32 byte) node references — rather than
    guessing. An unsupported proof shape is an error, never a silent pass.
  * The header reconstruction covers the post-merge field set through the
    Prague fork. A future fork that appends header fields will fail the hash
    check until the field list here is extended; that failure is loud.
  * Storage slot layout is taken from the reference AgentMemoryStateRegistry:
    `_spaces` at slot 0, SpaceRecord = {controller, authorizer, transitionId,
    stateRoot, (sequence | configNonce packed)}. A registry built from
    different source needs --base-slot or a different layout, and will
    otherwise report a mismatch that is a layout error, not a spec violation.
  * Spaces are enumerated from TransitionCommitted logs. A Space registered
    but never advanced has no transitions to check and does not appear.
  * This checks the state machine. It says nothing about whether committed
    memory is available, truthful, or meaningful — ERC-8350 is explicit about
    those being out of scope.

Companion to the ERC-8312 reference implementation in this repository. That
code implements meterable invariants in Solidity; this script is what checking
such an invariant from outside looks like — here applied to ERC-8350's public
deployment, whose transition rule is the same shape one layer up.
"""

import argparse
import json
import sys
import urllib.request

try:
    from Crypto.Hash import keccak
except ImportError:
    sys.exit("needs pycryptodome:  pip install pycryptodome")

DEFAULT_RPC = "https://sepolia.gateway.tenderly.co"
DEFAULT_REGISTRY = "0xDdf21937ba80b5fF973610877A0955b320C91241"

# keccak256("TransitionCommitted(bytes32,bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address)")
TRANSITION_COMMITTED_TOPIC = (
    "0x7294e8b186c350275762610b0f5718be9f4af95f7a7f8f8892381142f2afdde3")

# ERC-8350 "Transition ID" and "State transition" sections, byte for byte.
EXPERIENCE_DELTA_TYPE = (
    b"ExperienceDelta(bytes32 spaceId,uint64 sequence,bytes32 prevStateRoot,"
    b"bytes32 deltaCommitment,bytes32 provenanceCommitment,bytes32 profileId,"
    b"bytes32 locatorCommitment)")
MEMORY_STATE_TYPE = b"MemoryState(bytes32 prevStateRoot,bytes32 transitionId)"

UINT64_MASK = (1 << 64) - 1
UINT160_MASK = (1 << 160) - 1


# --------------------------------------------------------------------- hashing
def k256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


EXPERIENCE_DELTA_TYPEHASH = k256(EXPERIENCE_DELTA_TYPE)
MEMORY_STATE_TYPEHASH = k256(MEMORY_STATE_TYPE)

# keccak256(rlp(b"")) — the root of an empty trie.
EMPTY_TRIE_ROOT = bytes.fromhex(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")


def word(value) -> bytes:
    """32-byte big-endian word from an int, hex string, or bytes."""
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    if isinstance(value, str):
        value = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    return value.rjust(32, b"\0")


def hexs(data: bytes) -> str:
    return "0x" + data.hex()


# ------------------------------------------------------------------------ RLP
def rlp_encode(item) -> bytes:
    """RLP-encode bytes, or a (possibly nested) list of bytes."""
    if isinstance(item, (bytes, bytearray)):
        item = bytes(item)
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) < 56:
            return bytes([0x80 + len(item)]) + item
        length = len(item).to_bytes((len(item).bit_length() + 7) // 8, "big")
        return bytes([0xB7 + len(length)]) + length + item
    body = b"".join(rlp_encode(x) for x in item)
    if len(body) < 56:
        return bytes([0xC0 + len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + body


def rlp_decode(buf: bytes):
    """Strict RLP decode: bounds-checked, rejects trailing bytes."""
    def item(i):
        if i >= len(buf):
            raise ValueError("rlp: truncated input")
        prefix = buf[i]
        if prefix < 0x80:
            return buf[i:i + 1], i + 1
        if prefix < 0xB8:
            n = prefix - 0x80
            if i + 1 + n > len(buf):
                raise ValueError("rlp: truncated string")
            return buf[i + 1:i + 1 + n], i + 1 + n
        if prefix < 0xC0:
            ln = prefix - 0xB7
            n = int.from_bytes(buf[i + 1:i + 1 + ln], "big")
            if i + 1 + ln + n > len(buf):
                raise ValueError("rlp: truncated long string")
            return buf[i + 1 + ln:i + 1 + ln + n], i + 1 + ln + n
        if prefix < 0xF8:
            end = i + 1 + (prefix - 0xC0)
            j = i + 1
        else:
            ln = prefix - 0xF7
            n = int.from_bytes(buf[i + 1:i + 1 + ln], "big")
            end = i + 1 + ln + n
            j = i + 1 + ln
        if end > len(buf):
            raise ValueError("rlp: truncated list")
        out = []
        while j < end:
            value, j = item(j)
            out.append(value)
        return out, end

    decoded, consumed = item(0)
    if consumed != len(buf):
        raise ValueError("rlp: trailing bytes")
    return decoded


# ---------------------------------------------------------- Merkle-Patricia trie
def _nibbles(data: bytes):
    out = []
    for byte in data:
        out += [byte >> 4, byte & 0xF]
    return out


def verify_proof(root: bytes, key: bytes, proof) -> bytes:
    """Walk `proof` from `root` along keccak(key).

    Returns the RLP-encoded value stored at the key, or b"" if the key is
    proven absent. Raises ValueError on any malformed, unsupported, or
    non-matching proof — never guesses.
    """
    path = _nibbles(k256(key))
    depth = 0
    expected = root

    for raw in proof:
        if k256(raw) != expected:
            raise ValueError(f"proof node hash mismatch at depth {depth}")
        node = rlp_decode(raw)
        if not isinstance(node, list):
            raise ValueError(f"trie node at depth {depth} is not a list")

        if len(node) == 17:                                        # branch
            if depth == len(path):
                return node[16]
            nxt = node[path[depth]]
            depth += 1
        elif len(node) == 2:                                       # leaf | extension
            encoded = _nibbles(node[0])
            if not encoded:
                raise ValueError("empty hex-prefix path in trie node")
            flag = encoded[0]
            if flag > 3:
                raise ValueError(f"invalid hex-prefix flag {flag}")
            if flag in (0, 2):
                if len(encoded) < 2 or encoded[1] != 0:
                    raise ValueError("invalid hex-prefix padding")
                segment = encoded[2:]
            else:
                segment = encoded[1:]
            if path[depth:depth + len(segment)] != segment:
                return b""                                         # proven absent
            depth += len(segment)
            if flag in (2, 3):                                     # leaf
                return node[1] if depth == len(path) else b""
            nxt = node[1]
        else:
            raise ValueError(f"malformed trie node at depth {depth}")

        if isinstance(nxt, list) or (nxt != b"" and len(nxt) != 32):
            raise ValueError(
                "inlined (<32 byte) trie node reference; this minimal walker "
                "does not support that shape and refuses to guess")
        if nxt == b"":
            return b""
        expected = nxt

    raise ValueError("proof ended before the key was consumed")


def verify_account(state_root: bytes, address: str, account_proof) -> bytes:
    """Return the account's storage root, proven against state_root."""
    raw = verify_proof(state_root, bytes.fromhex(address[2:]), account_proof)
    if raw == b"":
        raise ValueError("account is absent from the state trie")
    fields = rlp_decode(raw)
    if not isinstance(fields, list) or len(fields) != 4:
        raise ValueError("malformed account leaf")
    return fields[2].rjust(32, b"\0")


def verify_slot(storage_root: bytes, slot: int, slot_proof) -> int:
    """Return the integer at `slot`, proven against storage_root."""
    if storage_root == EMPTY_TRIE_ROOT:
        return 0
    raw = verify_proof(storage_root, slot.to_bytes(32, "big"), slot_proof)
    return 0 if raw == b"" else int.from_bytes(rlp_decode(raw), "big")


# ----------------------------------------------------------------- block header
# Execution-layer header fields, post-merge through Prague. Optional fields are
# appended in fork order; presence is taken from the RPC response.
_HEADER_REQUIRED = [
    ("parentHash", bytes), ("sha3Uncles", bytes), ("miner", bytes),
    ("stateRoot", bytes), ("transactionsRoot", bytes), ("receiptsRoot", bytes),
    ("logsBloom", bytes), ("difficulty", int), ("number", int),
    ("gasLimit", int), ("gasUsed", int), ("timestamp", int),
    ("extraData", bytes), ("mixHash", bytes), ("nonce", bytes),
]
_HEADER_OPTIONAL = [
    ("baseFeePerGas", int), ("withdrawalsRoot", bytes),
    ("blobGasUsed", int), ("excessBlobGas", int),
    ("parentBeaconBlockRoot", bytes), ("requestsHash", bytes),
]


def _header_item(value, kind):
    if kind is int:
        n = int(value, 16)
        return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes.fromhex(value[2:])


def verify_header(block: dict):
    """Reconstruct the header, check keccak(rlp(header)) == reported hash.

    Returns (block_hash, state_root) as bytes. Raises on any mismatch, which
    means either a lying endpoint or a header shape this script predates.
    """
    fields = [_header_item(block[name], kind) for name, kind in _HEADER_REQUIRED]
    stopped = None
    for name, kind in _HEADER_OPTIONAL:
        value = block.get(name)
        if value is None:
            stopped = name
            continue
        if stopped is not None:
            raise ValueError(
                f"header has {name} but not earlier {stopped}; shape not recognized")
        fields.append(_header_item(value, kind))

    computed = k256(rlp_encode(fields))
    reported = bytes.fromhex(block["hash"][2:])
    if computed != reported:
        raise ValueError(
            f"header reconstruction mismatch: computed {hexs(computed)}, "
            f"endpoint reports {hexs(reported)} — lying endpoint or a header "
            f"shape newer than this script")
    return reported, bytes.fromhex(block["stateRoot"][2:])


# ------------------------------------------------------------------------ RPC
class Rpc:
    def __init__(self, url):
        self.url = url
        self._id = 0

    def __call__(self, method, params):
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id,
             "method": method, "params": params}).encode()
        request = urllib.request.Request(
            self.url, payload,
            {"Content-Type": "application/json",
             # some public gateways reject urllib's default user agent
             "User-Agent": "erc8350-recompute/1.0"})
        try:
            response = json.load(urllib.request.urlopen(request, timeout=90))
        except json.JSONDecodeError:
            raise RuntimeError(
                f"{method}: endpoint returned non-JSON (rate limited?)") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{method}: endpoint unreachable ({exc})") from None
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        if "result" not in response:
            raise RuntimeError(f"{method}: no result in response")
        return response["result"]


# ----------------------------------------------------------------------- main
def collect_spaces(rpc, registry):
    logs = rpc("eth_getLogs", [{"address": registry,
                                "topics": [TRANSITION_COMMITTED_TOPIC],
                                "fromBlock": "0x0", "toBlock": "latest"}])
    spaces = {}
    for log in logs:
        data = bytes.fromhex(log["data"][2:])
        if len(data) != 224:
            raise ValueError(
                f"TransitionCommitted data is {len(data)} bytes, expected 224")
        fields = [data[i * 32:(i + 1) * 32] for i in range(7)]
        spaces.setdefault(log["topics"][1].lower(), []).append({
            "sequence": int(log["topics"][3], 16),
            "transitionId": bytes.fromhex(log["topics"][2][2:]),
            "prevStateRoot": fields[0],
            "nextStateRoot": fields[1],
            "deltaCommitment": fields[2],
            "provenanceCommitment": fields[3],
            "profileId": fields[4],
            "locatorCommitment": fields[5],
            "authorizer": "0x" + fields[6][12:].hex(),
            "block": int(log["blockNumber"], 16),
            "tx": log["transactionHash"],
        })
    return len(logs), spaces


def replay_chain(space_id, transitions):
    """Recompute every advance from the raw event fields.

    Returns (ok, head_transition_id, head_root, head_sequence, rows). The
    running root is carried forward from the RECOMPUTED value, never from the
    log's claim, so the replayed head is derived entirely on this side.
    """
    prev_root, prev_sequence, ok, rows = bytes(32), 0, True, []
    head_tid = bytes(32)
    for t in transitions:
        transition_id = k256(b"".join([
            EXPERIENCE_DELTA_TYPEHASH, word(space_id), word(t["sequence"]),
            t["prevStateRoot"], t["deltaCommitment"], t["provenanceCommitment"],
            t["profileId"], t["locatorCommitment"]]))
        next_root = k256(MEMORY_STATE_TYPEHASH + t["prevStateRoot"] + transition_id)

        checks = {
            "id": transition_id == t["transitionId"],
            "root": next_root == t["nextStateRoot"],
            "link": t["prevStateRoot"] == prev_root,
            "seq": t["sequence"] == prev_sequence + 1,
        }
        ok &= all(checks.values())
        rows.append((t, checks))
        prev_root, prev_sequence = next_root, t["sequence"]
        head_tid = transition_id
    return ok, head_tid, prev_root, prev_sequence, rows


def prove_head(rpc, registry, space_id, block, state_root, base_slot):
    """Walk the trie to the Space's stored head. Returns proven values only.

    Every returned value comes from this side's walk of the submitted proof
    nodes: the requested slot list is authoritative, each response entry's key
    must equal the requested slot, and the walked value must equal the value
    the endpoint reported — any disagreement raises.
    """
    base = int.from_bytes(k256(word(space_id) + word(base_slot)), "big")
    names = ["controller", "authorizer", "transitionId", "stateRoot", "seqNonce"]
    slots = [(base + i) % (1 << 256) for i in range(5)]

    proof = rpc("eth_getProof",
                [registry, [f"0x{s:064x}" for s in slots], hex(block)])

    storage_root = verify_account(
        state_root, registry, [bytes.fromhex(n[2:]) for n in proof["accountProof"]])
    if storage_root != bytes.fromhex(proof["storageHash"][2:]):
        raise ValueError("storageHash disagrees with the walked account proof")

    entries = proof["storageProof"]
    if len(entries) != len(slots):
        raise ValueError(f"expected {len(slots)} storage proofs, got {len(entries)}")

    values = {}
    for name, slot, entry in zip(names, slots, entries):
        if int(entry["key"], 16) != slot:
            raise ValueError(f"endpoint returned proof for wrong slot on {name}")
        walked = verify_slot(storage_root, slot,
                             [bytes.fromhex(n[2:]) for n in entry["proof"]])
        if walked != int(entry["value"], 16):
            raise ValueError(f"walked value disagrees with the RPC on {name}")
        values[name] = walked

    for name in ("controller", "authorizer"):
        if values[name] & ~UINT160_MASK:
            raise ValueError(
                f"{name} slot holds more than an address; wrong --base-slot?")

    return {
        "account_nodes": len(proof["accountProof"]),
        "storage_root": storage_root,
        "transitionId": word(values["transitionId"]),
        "stateRoot": word(values["stateRoot"]),
        "sequence": values["seqNonce"] & UINT64_MASK,
        "configNonce": (values["seqNonce"] >> 64) & UINT64_MASK,
        "authorizer": f"0x{values['authorizer']:040x}",
        "controller": f"0x{values['controller']:040x}",
    }


def main():
    ap = argparse.ArgumentParser(
        description="Recompute the ERC-8350 transition rule from chain data.")
    ap.add_argument("--rpc-url", default=DEFAULT_RPC,
                    help="JSON-RPC endpoint (default: %(default)s)")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY,
                    help="registry address (default: the public Sepolia deployment)")
    ap.add_argument("--block", type=int, default=None,
                    help="observation block; default is head minus 12")
    ap.add_argument("--base-slot", type=int, default=0,
                    help="declaration slot of the _spaces mapping (default: 0)")
    ap.add_argument("--cross-check-rpc", default=None,
                    help="second endpoint that must report the same block hash "
                         "and state root")
    args = ap.parse_args()

    rpc = Rpc(args.rpc_url)
    registry = args.registry

    log_count, spaces = collect_spaces(rpc, registry)
    print(f"registry            {registry}")
    print(f"TransitionCommitted {log_count} logs across {len(spaces)} Memory Spaces")

    block_number = args.block if args.block is not None else \
        int(rpc("eth_blockNumber", []), 16) - 12
    block = rpc("eth_getBlockByNumber", [hex(block_number), False])
    if block is None:
        print(f"block {block_number} not available from this endpoint")
        return 1
    block_hash, state_root = verify_header(block)
    print(f"observation block   {block_number}")
    print(f"block hash          {hexs(block_hash)}   <- check this against any explorer")
    print(f"stateRoot           {hexs(state_root)}   (proven inside that header)")

    if args.cross_check_rpc:
        try:
            other = Rpc(args.cross_check_rpc)(
                "eth_getBlockByNumber", [hex(block_number), False])
        except RuntimeError as exc:
            print(f"CROSS-CHECK UNAVAILABLE: {exc}")
            print("a requested second opinion that cannot be obtained is a failure")
            return 1
        if other is None:
            print("cross-check endpoint does not have this block")
            return 1
        if (other["hash"].lower() != hexs(block_hash)
                or other["stateRoot"].lower() != hexs(state_root)):
            print("CROSS-CHECK FAILED: endpoints disagree about this block")
            return 1
        print(f"cross-check         {args.cross_check_rpc} agrees")
    print()

    if not spaces:
        print("no transitions found: nothing was verified (wrong registry, "
              "filtered logs, or a never-used deployment)")
        return 1

    all_ok = True
    for space_id, transitions in sorted(spaces.items()):
        transitions.sort(key=lambda t: t["sequence"])
        print("=" * 78)
        print(f"Memory Space {space_id}")

        chain_ok, head_tid, head_root, head_sequence, rows = \
            replay_chain(space_id, transitions)
        for t, checks in rows:
            mark = "OK  " if all(checks.values()) else "FAIL"
            detail = " ".join(f"{key}={'ok' if passed else 'MISMATCH'}"
                              for key, passed in checks.items())
            print(f"  [{mark}] seq {t['sequence']:>3}  {detail}"
                  f"  authorizer={t['authorizer']}  block={t['block']}")

        try:
            head = prove_head(rpc, registry, space_id, block_number,
                              state_root, args.base_slot)
        except RuntimeError as exc:
            if args.block is not None:
                print(f"\neth_getProof failed at block {block_number}: {exc}\n"
                      f"Most endpoints serve proofs only within a recent window. "
                      f"Re-run without --block to observe at the current head, or "
                      f"use an archive endpoint. The head is stable while no new "
                      f"transitions land, so a later observation block yields the "
                      f"same result.")
                return 1
            raise

        tid_match = head["transitionId"] == head_tid
        root_match = head["stateRoot"] == head_root
        seq_match = head["sequence"] == head_sequence

        print(f"  storage proof: account proof {head['account_nodes']} nodes, "
              f"walked storageRoot {hexs(head['storage_root'])[:18]}...")
        print(f"    stored transitionId {hexs(head['transitionId'])}")
        print(f"    replayed            {hexs(head_tid)}  "
              f"{'MATCH' if tid_match else 'MISMATCH'}")
        print(f"    stored stateRoot    {hexs(head['stateRoot'])}")
        print(f"    replayed            {hexs(head_root)}  "
              f"{'MATCH' if root_match else 'MISMATCH'}")
        print(f"    stored sequence     {head['sequence']}   "
              f"replayed {head_sequence}  {'MATCH' if seq_match else 'MISMATCH'}")
        print(f"    controller {head['controller']}  authorizer {head['authorizer']}"
              f"  configNonce {head['configNonce']}")

        verified = chain_ok and tid_match and root_match and seq_match
        all_ok &= verified
        if verified:
            print("  ==> VERIFIED-GOOD: every advance recomputes, the chain is "
                  "gapless, and the stored head equals the replayed path")
        else:
            print("  ==> FAILED: see the mismatches above")

    print("\n" + "=" * 78)
    print("RESULT:", "ALL SPACES VERIFIED-GOOD" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
