// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendPreimage} from "../src/SpendPreimage.sol";
import {SpendPreimageV2} from "../src/SpendPreimageV2.sol";

/// @notice Proves the v2 (payee-committed) preimage is byte-exact against its pinned
///         vector, that it binds the payee without revealing it, and that the v1
///         construction really does reveal it — the positive control that keeps the
///         confidentiality regression honest.
contract SpendPreimageV2Test is Test {
    // ---- same draw as the v1 pinned vector (Chiado, chainId 10200) ---- //
    uint256 internal constant AMOUNT = 500000000000000;
    uint256 internal constant CHAINID = 10200;
    address internal constant CURSOR_ID = 0x0000000000000000000000000000000000008312;
    bytes32 internal constant NONCE = 0x2fa8e52ccdf87e21b956e1c405f849cb549b528ce16f4c08893e353160748fe1;
    address internal constant PAYEE = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;
    address internal constant SAFE = 0xb7e493e3d226f8fE722CC9916fF164B793af13F4;
    // TEST VECTOR ONLY: sha256("spend.v2 vector blinding") — publicly derived so the
    // vector reproduces. Production blindings follow the library natspec: CSPRNG or
    // secret-keyed PRF, never derived from public or guessable inputs.
    bytes32 internal constant BLINDING = 0xa79dd3df572859e3947edf330cbb120a945ddb4a054fc7f6880f04e558a3d972;

    string internal constant EXPECTED_COMMITMENT_STRING =
        '{"blinding":"0xa79dd3df572859e3947edf330cbb120a945ddb4a054fc7f6880f04e558a3d972","payee":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045","safeAddress":"0xb7e493e3d226f8fe722cc9916ff164b793af13f4"}';
    bytes32 internal constant EXPECTED_COMMITMENT =
        0x75f42d4c332c5a2b83df2b5221a6914719c9aacef918cb379a12172e42786ca4;
    string internal constant EXPECTED_STRING =
        '{"amountWei":"500000000000000","chainId":"10200","cursorId":"0x0000000000000000000000000000000000008312","nonce":"0x2fa8e52ccdf87e21b956e1c405f849cb549b528ce16f4c08893e353160748fe1","payeeCommitment":"0x75f42d4c332c5a2b83df2b5221a6914719c9aacef918cb379a12172e42786ca4"}';
    bytes32 internal constant EXPECTED_HASH = 0xa7dd3012165139d1a887a1f4141b6609d6e2c948acc56d17d423d7548c431049;

    // lowercase hex of the payee / safe addresses, without "0x" — the byte patterns
    // whose absence from the public preimage IS the confidentiality claim
    bytes internal constant PAYEE_HEX = "d8da6bf26964af9d7eed9e03e53415d37aa96045";
    bytes internal constant SAFE_HEX = "b7e493e3d226f8fe722cc9916ff164b793af13f4";

    function _commitment() internal pure returns (bytes32) {
        return SpendPreimageV2.payeeCommitment(PAYEE, SAFE, BLINDING);
    }

    function _hashVector() internal pure returns (bytes32) {
        return SpendPreimageV2.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, _commitment());
    }

    // ---- alignment with the pinned vector ---- //

    function test_commitmentCanonical_matchesVectorStringByteForByte() public {
        assertEq(SpendPreimageV2.commitmentCanonical(PAYEE, SAFE, BLINDING), EXPECTED_COMMITMENT_STRING);
    }

    function test_commitment_matchesPinnedVector() public {
        assertEq(_commitment(), EXPECTED_COMMITMENT);
    }

    function test_canonical_matchesVectorStringByteForByte() public {
        assertEq(SpendPreimageV2.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, _commitment()), EXPECTED_STRING);
    }

    function test_hash_matchesPinnedVector() public {
        assertEq(_hashVector(), EXPECTED_HASH);
    }

    function test_hash_equalsSha256OfLiteralPreimage() public {
        // independent path: the library hash equals sha256 over the literal canonical bytes
        assertEq(_hashVector(), sha256(bytes(EXPECTED_STRING)));
    }

    // ---- the confidentiality claim, made falsifiable ---- //

    function test_confidentiality_payeeBytesAbsentFromV2Preimage() public {
        bytes memory pre = bytes(SpendPreimageV2.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, _commitment()));
        assertFalse(_contains(pre, PAYEE_HEX), "payee hex leaked into v2 preimage");
        assertFalse(_contains(pre, SAFE_HEX), "safe hex leaked into v2 preimage");
    }

    function test_confidentiality_detectorSelfTest_v1RevealsPayee() public {
        // positive control: the SAME detector finds both addresses in the v1 canonical,
        // so a pass on the v2 test is a real absence, not a blind scanner
        bytes memory v1 = bytes(SpendPreimage.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE));
        assertTrue(_contains(v1, PAYEE_HEX), "detector failed to find payee in v1");
        assertTrue(_contains(v1, SAFE_HEX), "detector failed to find safe in v1");
    }

    // ---- the binding: the commitment pins exactly one payment destination ---- //

    function test_binding_differentPayeeChangesCommitmentAndHash() public {
        bytes32 other = SpendPreimageV2.payeeCommitment(address(0xBEEF), SAFE, BLINDING);
        assertTrue(other != _commitment());
        assertTrue(SpendPreimageV2.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, other) != _hashVector());
    }

    function test_binding_differentSafeChangesCommitment() public {
        assertTrue(SpendPreimageV2.payeeCommitment(PAYEE, address(0xBEEF), BLINDING) != _commitment());
    }

    function test_unlinkability_freshBlindingChangesCommitment() public {
        // same payee, fresh blinding: two draws to one counterparty are unlinkable on the record
        assertTrue(SpendPreimageV2.payeeCommitment(PAYEE, SAFE, bytes32(uint256(1))) != _commitment());
    }

    function test_binding_amountTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimageV2.hash(AMOUNT + 1, CHAINID, CURSOR_ID, NONCE, _commitment()));
    }

    function test_binding_chainTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimageV2.hash(AMOUNT, 100, CURSOR_ID, NONCE, _commitment()));
    }

    function test_binding_cursorIdTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimageV2.hash(AMOUNT, CHAINID, address(0x1234), NONCE, _commitment()));
    }

    function test_binding_nonceTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimageV2.hash(AMOUNT, CHAINID, CURSOR_ID, bytes32(uint256(1)), _commitment()));
    }

    function test_versionSeparation_v1AndV2DigestsDiffer() public {
        // disjoint canonical formats; a collision would be a sha256 collision —
        // this checks the pinned instance, the structural test below carries the claim
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE));
    }

    function test_versionSeparation_structuralDisjointness() public {
        // the actual argument: every v2 canonical contains the literal key
        // "payeeCommitment", which no v1 canonical can contain (v1 values are
        // restricted to [0-9a-fx] and cannot impersonate a key), so the two
        // canonical string sets are disjoint
        bytes memory v2c = bytes(SpendPreimageV2.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, _commitment()));
        bytes memory v1c = bytes(SpendPreimage.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE));
        assertTrue(_contains(v2c, bytes('"payeeCommitment":"')), "v2 canonical lost its distinguishing key");
        assertFalse(_contains(v1c, bytes('"payeeCommitment":"')), "v1 canonical must not contain the v2 key");
    }

    function test_binding_commitmentTamperChangesHash() public {
        bytes32 tampered = _commitment() ^ bytes32(uint256(1));
        assertTrue(_hashVector() != SpendPreimageV2.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, tampered));
    }

    function testFuzz_binding_payeeChangesCommitmentAndHash(address p) public {
        vm.assume(p != PAYEE);
        bytes32 other = SpendPreimageV2.payeeCommitment(p, SAFE, BLINDING);
        assertTrue(other != _commitment());
        assertTrue(SpendPreimageV2.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, other) != _hashVector());
    }

    // ---- helpers ---- //

    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        if (needle.length == 0 || needle.length > haystack.length) return false;
        for (uint256 i = 0; i + needle.length <= haystack.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
