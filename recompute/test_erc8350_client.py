"""Tests for the independent ERC-8350 client.

The conformance tests fetch the pinned inputs. Set ERC8350_INPUTS to a
directory holding them to run offline; set ERC8350_OFFLINE=1 to skip the tests
that need them. The mutant registries below each break one rule, and each must
be caught by the check written for that rule: a check that cannot fail is not
evidence.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("erc8350_client", HERE / "erc8350_client.py")
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

OFFLINE = os.environ.get("ERC8350_OFFLINE") == "1"
_RAW = None


def pinned_inputs():
    global _RAW
    if _RAW is None:
        _RAW = client.load_inputs(os.environ.get("ERC8350_INPUTS"))
    return _RAW


def failed(rep, layer):
    return [c["check"] for c in rep.checks[layer] if not c["pass"]]


def b(hexstr):
    return bytes.fromhex(hexstr[2:])


class PrimitiveTest(unittest.TestCase):
    def test_typehashes_are_the_drafts_printed_values(self):
        # ERC-8350 "Test Cases" section.
        self.assertEqual(client.hexs(client.EXPERIENCE_DELTA_TYPEHASH),
                         "0x4f020f86bc06d852f1fde17853b4d92a70214eeab8e09718028124af097d070d")
        self.assertEqual(client.hexs(client.MEMORY_STATE_TYPEHASH),
                         "0xf3148762556cbf851baf4b9a205e18ff4e6b366a58a3a1ef58e8626ba41beadb")
        self.assertEqual(client.hexs(client.MEMORY_SPACE_TYPEHASH),
                         "0x9ae5478f084ad3b841da58a9cb2354d153cddec59ee64d0cb741fa9d08884531")

    def test_private_key_one_address(self):
        self.assertEqual(client.hexs(client.address_of(1)),
                         "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")

    def test_signature_matches_an_independent_signer(self):
        # Produced by `cast wallet sign --no-hash` (Foundry 1.8.3) for the same
        # key and digest. RFC 6979 makes the bytes deterministic for digests
        # below n; cast derives its nonce from the unreduced digest above n.
        digest = client.k256(b"cross-check authorizer 0")
        self.assertEqual(client.hexs(digest),
                         "0xff2526bf05e576bb9b036d75b4215878a3d7bbb01d6a9c8ab07dedf61fdfe5cd")
        self.assertEqual(
            client.hexs(client.ecdsa_sign(client._test_key("authorizer"), digest)),
            "0xac80cb280cbf968c86dcd75a1a24f04fcc2b2f4975ff6ec85b7d719d8eaf240c"
            "58094169ba4d91afd6e3e5878e94d9c14363cbf5279d19a6015934acf177c77d1b")

    def test_recovery_refuses_non_canonical_encodings(self):
        key = client._test_key("authorizer")
        digest = client.k256(b"recovery")
        sig = client.ecdsa_sign(key, digest)
        self.assertEqual(client.ecdsa_recover(digest, sig), client.address_of(key))
        r, v = sig[:32], sig[64]
        n = client.N
        high_s = client.malleate(sig)
        # The malleated twin is a valid signature in every respect but s: same
        # key without the low-s rule, v still 27 or 28.
        self.assertIn(high_s[64], (27, 28))
        self.assertEqual(client._recover_unchecked(digest, high_s), client.address_of(key))
        cases = {
            "high-s": high_s,
            "v 0/1": sig[:64] + bytes([v - 27]),
            # x = 0 is not on secp256k1, so this is refused with or without the
            # 0 < r rule; it is here as an input, not as evidence for that rule.
            "r = 0": b"\x00" * 32 + sig[32:],
            "s = 0": r + b"\x00" * 32 + sig[64:],
            "r = n": n.to_bytes(32, "big") + sig[32:],
            "s = n": r + n.to_bytes(32, "big") + sig[64:],
            "64 bytes": sig[:64],
            "66 bytes": sig + b"\x00",
        }
        for label, bad in cases.items():
            with self.subTest(label):
                self.assertIsNone(client.ecdsa_recover(digest, bad))

    def test_rejection_leaves_the_registry_unchanged(self):
        reg = client.Registry(1, b"\x44" * 20)
        controller = client.address_of(client._test_key("controller"))
        salt = client.k256(b"salt")
        sid = client.space_id_of(controller, salt)
        reg.register_space(controller, sid, controller, controller, salt)
        before = reg.snapshot()
        bad = client.Delta(sid, 2, client.ZERO32, b"\x01" * 32, client.ZERO32,
                           b"\x02" * 32, client.ZERO32)
        with self.assertRaises(client.Rejected):
            reg.commit_transition(controller, bad)
        self.assertEqual(reg.snapshot(), before)

    def test_duplicate_guard_refuses_even_if_the_head_were_rolled_back(self):
        # Unreachable through the public calls (see the module docstring); this
        # forces the state that would reach it and checks nothing is overwritten.
        reg = client.Registry(1, b"\x44" * 20)
        controller = client.address_of(client._test_key("controller"))
        salt = client.k256(b"salt")
        sid = client.space_id_of(controller, salt)
        reg.register_space(controller, sid, controller, controller, salt)
        d = client.Delta(sid, 1, client.ZERO32, b"\x01" * 32, client.ZERO32, b"\x02" * 32,
                         client.ZERO32)
        reg.commit_transition(controller, d)
        stored = dict(reg.transitions)
        rec = reg.spaces[sid]
        rec.head_transition_id, rec.head_state_root, rec.head_sequence = (
            client.ZERO32, client.ZERO32, 0)
        with self.assertRaises(client.Rejected) as ctx:
            reg.commit_transition(controller, d)
        self.assertEqual(ctx.exception.name, "TransitionAlreadyExists")
        self.assertEqual(reg.transitions, stored)

    def test_signature_vectors_are_refused_from_a_failing_run(self):
        rep = client.Report()
        for layer in client.LAYERS:
            rep.check(layer, "x", True)
        client.signature_vector_file(rep, [])
        rep.check("ecdsa", "y", False)
        with self.assertRaises(RuntimeError):
            client.signature_vector_file(rep, [])


@unittest.skipIf(OFFLINE, "ERC8350_OFFLINE=1")
class ConformanceTest(unittest.TestCase):
    def test_every_layer_passes(self):
        rep = client.run_all(pinned_inputs())
        for layer in client.LAYERS:
            with self.subTest(layer):
                self.assertTrue(rep.passed(layer), failed(rep, layer))

    def test_a_tampered_input_is_refused(self):
        raw = pinned_inputs()
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in raw.items():
                Path(tmp, name).write_bytes(data)
            client.load_inputs(tmp)
            Path(tmp, "v2.json").write_bytes(raw["v2.json"].replace(b"0x117e", b"0x117f", 1))
            with self.assertRaises(RuntimeError):
                client.load_inputs(tmp)

    def test_a_wrong_expected_value_fails_the_hash_layer(self):
        raw = dict(pinned_inputs())
        v2 = json.loads(raw["v2.json"])
        v2["chain"][2]["expected"]["transitionId"] = "0x" + "00" * 32
        raw["v2.json"] = json.dumps(v2).encode()
        rep = client.run_all(raw)
        self.assertIn("v2 with-locator transitionId", failed(rep, "hash"))

    def vectors(self):
        vectors = []
        rep = client.run_all(pinned_inputs(), vectors)
        return client.signature_vector_file(rep, vectors)["cases"]

    def test_signature_vectors_are_self_consistent(self):
        vectors = self.vectors()
        self.assertGreaterEqual(len(vectors), 46)
        for v in vectors:
            with self.subTest(v["case"]):
                self.assertIn("call", v)
                sig = b(v["signature"])
                checked = b(v["signingDigest"])
                if not sig:
                    if v["expected"] == "accept":
                        self.assertEqual(v["sender"], v["requiredAccount"])
                    else:
                        self.assertEqual(v["refusedBy"], "length")
                    continue
                if v.get("defect"):
                    self.assertIn(v["refusedBy"], ("length", "noncanonical"))
                    self.assertIsNone(client.ecdsa_recover(checked, sig))
                    continue
                signed = b(v.get("signedDigest", v["signingDigest"]))
                self.assertEqual(client.hexs(client.ecdsa_recover(signed, sig)), v["signer"])
                if v["expected"] == "accept":
                    self.assertEqual(v["signer"], v["requiredAccount"])
                    self.assertNotIn("signedDigest", v)
                elif v["refusedBy"] == "signer":
                    self.assertNotEqual(client.hexs(client.ecdsa_recover(checked, sig)),
                                        v["requiredAccount"])
                else:
                    # Refused by a state rule: the signature itself is good.
                    self.assertEqual(client.hexs(client.ecdsa_recover(checked, sig)),
                                     v["requiredAccount"])

    @unittest.skipIf(shutil.which("cast") is None, "cast not installed")
    def test_signers_verify_under_cast(self):
        # Independent of this file's recovery code: every canonical signature
        # verifies for its named signer over what was signed, and every
        # wrong-signer refusal fails to verify for the required account.
        def verifies(address, digest, sig):
            out = subprocess.run(["cast", "wallet", "verify", "--no-hash", "--address",
                                  address, digest, sig], capture_output=True, text=True)
            return out.returncode == 0

        for v in self.vectors():
            if v.get("defect") or v["signature"] == "0x":
                continue
            with self.subTest(v["case"]):
                self.assertTrue(verifies(v["signer"], v.get("signedDigest", v["signingDigest"]),
                                         v["signature"]))
                if v.get("refusedBy") == "signer":
                    self.assertFalse(verifies(v["requiredAccount"], v["signingDigest"],
                                              v["signature"]))


# Each mutant breaks one rule. The named check must fail.
class Patched(client.Registry):
    """Swaps in a replacement _authorize for the duration of one operation."""

    def _with_auth(self, auth, op, *args, **kwargs):
        self._authorize = auth
        try:
            return op(*args, **kwargs)
        finally:
            del self._authorize


class SkipsRegistrationAuthorization(Patched):
    def register_space(self, *args, **kwargs):
        return self._with_auth(lambda *a: "ecdsa", super().register_space, *args, **kwargs)


class ControllerMayCommit(Patched):
    def commit_transition(self, sender, delta, signature=b""):
        rec, base = self.spaces.get(delta.space_id), client.Registry._authorize

        def auth(required, s, h, sig):
            try:
                return base(self, required, s, h, sig)
            except client.Rejected:
                if rec is None:
                    raise
                return base(self, rec.controller, s, h, sig)
        return self._with_auth(auth, super().commit_transition, sender, delta, signature)


class EmptyFromAnyCaller(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if not signature:
            return "direct-empty"
        return super()._authorize(required, sender, struct_hash, signature)


class RotationKeepsController(client.Registry):
    def update_space_authorization(self, sender, space_id, *args, **kwargs):
        rec = self.spaces.get(client.b32(space_id))
        old = rec.controller if rec else None
        path = super().update_space_authorization(sender, space_id, *args, **kwargs)
        rec.controller = old
        return path


class RotationAllowsZero(client.Registry):
    def update_space_authorization(self, sender, space_id, new_controller, new_authorizer,
                                   signature=b""):
        space_id = client.b32(space_id)
        rec = self._space(space_id)
        nonce = rec.config_nonce + 1
        path = self._authorize(rec.controller, client.addr(sender),
                               client.authorization_hash(space_id, client.addr(new_controller),
                                                         client.addr(new_authorizer), nonce),
                               signature)
        rec.controller, rec.authorizer, rec.config_nonce = (
            client.addr(new_controller), client.addr(new_authorizer), nonce)
        return path


class RegistrationAllowsZeroAuthorizer(client.Registry):
    def register_space(self, sender, space_id, controller, authorizer, salt, signature=b""):
        if client.addr(authorizer) == client.ZERO20:
            space_id = client.b32(space_id)
            if client.space_id_of(client.addr(controller), salt) != space_id:
                raise client.Rejected("InvalidSpaceId", "derivation")
            self.spaces[space_id] = client.SpaceRecord(client.addr(controller), client.ZERO20,
                                                       0, client.ZERO32, client.ZERO32, 0)
            return "direct-empty"
        return super().register_space(sender, space_id, controller, authorizer, salt, signature)


class DropsZeroAddressRule(RegistrationAllowsZeroAuthorizer):
    def register_space(self, sender, space_id, controller, authorizer, salt, signature=b""):
        if client.addr(controller) == client.ZERO20:
            space_id = client.b32(space_id)
            if client.space_id_of(client.ZERO20, salt) != space_id:
                raise client.Rejected("InvalidSpaceId", "derivation")
            self.spaces[space_id] = client.SpaceRecord(client.ZERO20, client.addr(authorizer),
                                                       0, client.ZERO32, client.ZERO32, 0)
            return "direct-empty"
        return super().register_space(sender, space_id, controller, authorizer, salt, signature)


class AcceptsCompactSignatures(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if len(signature) == 64:
            ys = int.from_bytes(signature[32:], "big")
            signature = (signature[:32] + (ys & ((1 << 255) - 1)).to_bytes(32, "big")
                         + bytes([27 + (ys >> 255)]))
        return super()._authorize(required, sender, struct_hash, signature)


class DomainIgnoresChain(client.Registry):
    def __init__(self, chain_id, address, **kwargs):
        super().__init__(chain_id, address, **kwargs)
        self.domain = client.domain_separator(1, self.address)


class EventMissingCommitments(client.Registry):
    def commit_transition(self, sender, delta, signature=b""):
        out = super().commit_transition(sender, delta, signature)
        self.events[-1] = self.events[-1][:6] + self.events[-1][-1:]
        return out


class SkipsSequenceCheck(client.Registry):
    def commit_transition(self, sender, delta, signature=b""):
        rec = self.spaces.get(delta.space_id)
        if rec is not None:
            rec.head_sequence = delta.sequence - 1
        return super().commit_transition(sender, delta, signature)


class SkipsLinkageCheck(client.Registry):
    def commit_transition(self, sender, delta, signature=b""):
        rec = self.spaces.get(delta.space_id)
        if rec is not None:
            rec.head_state_root = delta.prev_state_root
        return super().commit_transition(sender, delta, signature)


class AllowsReRegistration(client.Registry):
    def register_space(self, sender, space_id, *args, **kwargs):
        self.spaces.pop(client.b32(space_id), None)
        return super().register_space(sender, space_id, *args, **kwargs)


class WritesBeforeChecking(client.Registry):
    def commit_transition(self, sender, delta, signature=b""):
        self.events.append(("attempt", delta.space_id, delta.sequence))
        return super().commit_transition(sender, delta, signature)


class AcceptsHighS(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if len(signature) == 65 and int.from_bytes(signature[32:64], "big") > client.HALF_N:
            signature = client.malleate(signature)
        return super()._authorize(required, sender, struct_hash, signature)


class NormalizesV(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if len(signature) == 65 and signature[64] in (0, 1):
            signature = signature[:64] + bytes([signature[64] + 27])
        return super()._authorize(required, sender, struct_hash, signature)


class IgnoresRotationNonce(client.Registry):
    def update_space_authorization(self, sender, space_id, *args, **kwargs):
        rec = self.spaces.get(client.b32(space_id))
        if rec is not None:
            rec.config_nonce = 0
        return super().update_space_authorization(sender, space_id, *args, **kwargs)


class DirectEmptyByNewController(client.Registry):
    def update_space_authorization(self, sender, space_id, new_controller, new_authorizer,
                                   signature=b""):
        if not signature and client.addr(sender) == client.addr(new_controller):
            rec = self._space(client.b32(space_id))
            rec.controller, rec.authorizer = client.addr(new_controller), client.addr(new_authorizer)
            rec.config_nonce += 1
            return "direct-empty"
        return super().update_space_authorization(sender, space_id, new_controller,
                                                  new_authorizer, signature)


class DirectEmptyByAnySpaceRole(Patched):
    """An empty signature from the controller OR the authorizer authorizes rotation."""

    def update_space_authorization(self, sender, space_id, *args, **kwargs):
        rec, base = self.spaces.get(client.b32(space_id)), client.Registry._authorize

        def auth(required, s, struct_hash, signature):
            if not signature and rec is not None and s in (rec.controller, rec.authorizer):
                return "direct-empty"
            return base(self, required, s, struct_hash, signature)
        return self._with_auth(auth, super().update_space_authorization, sender, space_id,
                               *args, **kwargs)


class NonceAlwaysOne(client.Registry):
    """Checks every rotation signature over nonce 1, but stores the right nonce."""

    def update_space_authorization(self, sender, space_id, new_controller, new_authorizer,
                                   signature=b""):
        rec = self._space(client.b32(space_id))
        real = rec.config_nonce
        rec.config_nonce = 0
        try:
            path = super().update_space_authorization(sender, space_id, new_controller,
                                                      new_authorizer, signature)
        except Exception:
            rec.config_nonce = real
            raise
        rec.config_nonce = real + 1
        self.events[-1] = self.events[-1][:-1] + (real + 1,)
        return path


class SelfCallSkipsValidation(Patched):
    """Any bytes from the required account authorize registration and rotation."""

    def _lax(self):
        base = client.Registry._authorize

        def auth(required, sender, struct_hash, signature):
            if sender == required:
                return "direct-empty"
            return base(self, required, sender, struct_hash, signature)
        return auth

    def register_space(self, *args, **kwargs):
        return self._with_auth(self._lax(), super().register_space, *args, **kwargs)

    def update_space_authorization(self, *args, **kwargs):
        return self._with_auth(self._lax(), super().update_space_authorization, *args, **kwargs)


class HardcodedDomain(client.Registry):
    def __init__(self, chain_id, address, **kwargs):
        super().__init__(chain_id, address, **kwargs)
        self.domain = client.domain_separator(client.ECDSA_CHAIN_ID, client.ECDSA_REGISTRY)


class EventFieldsOutOfOrder(client.Registry):
    def commit_transition(self, sender, delta, signature=b""):
        out = super().commit_transition(sender, delta, signature)
        e = list(self.events[-1])
        e[8], e[9] = e[9], e[8]  # profileId <-> locatorCommitment
        self.events[-1] = tuple(e)
        return out


class AcceptsOneOverHalfN(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if len(signature) == 65 and int.from_bytes(signature[32:64], "big") == client.HALF_N + 1:
            signature = client.malleate(signature)
        return super()._authorize(required, sender, struct_hash, signature)


class AcceptsRAboveN(client.Registry):
    def _authorize(self, required, sender, struct_hash, signature):
        if len(signature) == 65:
            r, s, v = client._split(signature)
            if r >= client.N and v in (27, 28):
                got = client._recover_raw(client.signing_digest(self.domain, struct_hash),
                                          r, s, v - 27)
                if got == required:
                    return "ecdsa"
        return super()._authorize(required, sender, struct_hash, signature)


class UnknownIsEmpty(client.Registry):
    """Treats an unregistered Space as an empty one with no accounts. Normatively
    fine: everything it should refuse is still refused, by another rule."""

    def _space(self, space_id):
        rec = self.spaces.get(space_id)
        if rec is None:
            return client.SpaceRecord(client.ZERO20, client.ZERO20, 0, client.ZERO32,
                                      client.ZERO32, 0)
        return rec


@unittest.skipIf(OFFLINE, "ERC8350_OFFLINE=1")
class MutantTest(unittest.TestCase):
    def assertCaught(self, mutant, layer, check):
        rep = client.run_all(pinned_inputs(), registry_cls=mutant)
        self.assertFalse(rep.passed(layer), f"{mutant.__name__} passed the {layer} layer")
        self.assertIn(check, failed(rep, layer))

    def test_registration_without_authorization_is_caught(self):
        self.assertCaught(SkipsRegistrationAuthorization, "ecdsa",
                          "register front-run: the controller's signature with another authorizer")

    def test_controller_approving_transitions_is_caught(self):
        self.assertCaught(ControllerMayCommit, "ecdsa",
                          "commit #1 signed by the controller, not the authorizer")

    def test_relayed_empty_signature_is_caught_for_every_operation(self):
        for check in ("register relayed with an empty signature",
                      "commit #2 empty signature from a relayer",
                      "rotation 1 relayed with an empty signature"):
            with self.subTest(check):
                self.assertCaught(EmptyFromAnyCaller, "ecdsa", check)

    def test_rotation_that_keeps_the_controller_is_caught(self):
        self.assertCaught(RotationKeepsController, "ecdsa", "rotation 2 replaced the controller")

    def test_zero_rotation_targets_are_caught(self):
        for check in ("rotation to a zero controller", "rotation to a zero authorizer"):
            with self.subTest(check):
                self.assertCaught(RotationAllowsZero, "ecdsa", check)

    def test_zero_authorizer_at_registration_is_caught(self):
        self.assertCaught(RegistrationAllowsZeroAuthorizer, "state",
                          "refuse zero authorizer at registration (spaceId re-derives)")

    def test_dropped_zero_address_rule_is_caught_normatively(self):
        self.assertCaught(DropsZeroAddressRule, "state",
                          "refuse zero controller at registration (spaceId re-derives from it)")

    def test_compact_signature_acceptance_is_caught_in_both_layers(self):
        self.assertCaught(AcceptsCompactSignatures, "state",
                          "refuse InvalidAuthorization (malformed length)")
        self.assertCaught(AcceptsCompactSignatures, "ecdsa",
                          "commit #2 compact 64-byte (EIP-2098) encoding")

    def test_domain_that_ignores_the_chain_is_caught(self):
        self.assertCaught(DomainIgnoresChain, "ecdsa",
                          "register relayed with the controller's signature")

    def test_incomplete_event_is_caught(self):
        self.assertCaught(EventMissingCommitments, "state",
                          "commit genesis-minimal TransitionCommitted event")

    def test_sequence_gap_is_caught(self):
        self.assertCaught(SkipsSequenceCheck, "state", "refuse BadSequence (skips ahead)")

    def test_sequence_replay_is_caught(self):
        self.assertCaught(SkipsSequenceCheck, "state",
                          "refuse BadSequence (replays a committed sequence)")

    def test_fork_from_an_earlier_root_is_caught(self):
        self.assertCaught(SkipsLinkageCheck, "state", "refuse BadPreviousState")

    def test_re_registration_is_caught(self):
        self.assertCaught(AllowsReRegistration, "state", "refuse SpaceAlreadyRegistered")

    def test_partial_write_on_rejection_is_caught(self):
        self.assertCaught(WritesBeforeChecking, "state", "refuse ZeroDeltaCommitment")

    def test_malleable_signature_is_caught(self):
        self.assertCaught(AcceptsHighS, "ecdsa", "commit #2 high-s (malleated) signature")

    def test_v_normalization_is_caught_and_later_cases_keep_their_rule(self):
        rep = client.run_all(pinned_inputs(), registry_cls=NormalizesV)
        bad = failed(rep, "ecdsa")
        self.assertTrue(any(c.startswith("commit #2 v = ") for c in bad), bad)
        # The accepted bad case advances the head; every later commit #2 refusal
        # now fires the sequence rule, and must be reported as the wrong rule.
        self.assertIn("commit #2 66-byte padded signature", bad)

    def test_rotation_replay_is_caught(self):
        self.assertCaught(IgnoresRotationNonce, "ecdsa",
                          "rotation 1 replayed by the same controller (nonce is now 2)")


    def test_direct_call_rotation_by_the_wrong_account_is_caught(self):
        self.assertCaught(DirectEmptyByNewController, "ecdsa",
                          "rotation 2 by direct call from the proposed new controller")
        self.assertCaught(DirectEmptyByAnySpaceRole, "ecdsa",
                          "rotation 1 by direct call from the authorizer, not the controller")

    def test_nonce_rule_is_what_refuses_the_replay(self):
        self.assertCaught(NonceAlwaysOne, "ecdsa",
                          "rotation 1 replayed by the same controller (nonce is now 2)")

    def test_self_call_bytes_are_validated_for_every_operation(self):
        for check in ("register self-call by the controller with an outsider's bytes",
                      "rotation 1 self-call by the controller with an outsider's bytes"):
            with self.subTest(check):
                self.assertCaught(SelfCallSkipsValidation, "ecdsa", check)

    def test_domain_fixed_at_one_deployment_is_caught(self):
        self.assertCaught(HardcodedDomain, "ecdsa",
                          "second deployment accepts a registration signed for it")

    def test_event_fields_out_of_draft_order_are_caught(self):
        self.assertCaught(EventFieldsOutOfOrder, "state",
                          "commit genesis-minimal TransitionCommitted event")

    def test_low_s_bound_is_exact(self):
        self.assertCaught(AcceptsOneOverHalfN, "ecdsa",
                          "commit with s = n/2 + 1, one over the low-s bound")

    def test_r_at_or_above_n_is_caught(self):
        rep = client.run_all(pinned_inputs(), registry_cls=AcceptsRAboveN)
        self.assertTrue(any(c.startswith("commit with r = n + ") for c in failed(rep, "ecdsa")),
                        failed(rep, "ecdsa"))

    def test_a_valid_alternative_check_order_is_not_failed_normatively(self):
        rep = client.run_all(pinned_inputs(), registry_cls=UnknownIsEmpty)
        for layer in ("state", "ecdsa"):
            with self.subTest(layer):
                self.assertTrue(rep.passed(layer), failed(rep, layer))
        self.assertIn("UnknownSpace: error name", failed(rep, "compat"))


if __name__ == "__main__":
    unittest.main()
