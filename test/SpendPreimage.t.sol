// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendPreimage} from "../src/SpendPreimage.sol";

/// @notice Proves the on-chain reconstruction is byte-for-byte identical to
///         GhostAgent's pinned off-chain canonical form (8004 thread #238), then
///         shows the binding holds: tampering any field changes the hash.
contract SpendPreimageTest is Test {
    // ---- GhostAgent's pinned vector (Chiado, chainId 10200) ---- //
    uint256 internal constant AMOUNT = 500000000000000;
    uint256 internal constant CHAINID = 10200;
    address internal constant CURSOR_ID = 0x0000000000000000000000000000000000008312;
    bytes32 internal constant NONCE = 0x2fa8e52ccdf87e21b956e1c405f849cb549b528ce16f4c08893e353160748fe1;
    address internal constant PAYEE = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;
    address internal constant SAFE = 0xb7e493e3d226f8fE722CC9916fF164B793af13F4;

    string internal constant EXPECTED_STRING =
        '{"amountWei":"500000000000000","chainId":"10200","cursorId":"0x0000000000000000000000000000000000008312","nonce":"0x2fa8e52ccdf87e21b956e1c405f849cb549b528ce16f4c08893e353160748fe1","payee":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045","safeAddress":"0xb7e493e3d226f8fe722cc9916ff164b793af13f4"}';
    bytes32 internal constant EXPECTED_HASH = 0x2775c208604080bcf9e511297ab0fe2ce5ef485b7616ac34acefcb7db2fb9a27;

    function _hashVector() internal pure returns (bytes32) {
        return SpendPreimage.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE);
    }

    // ---- alignment with the pinned vector ---- //

    function test_canonical_matchesVectorStringByteForByte() public {
        assertEq(SpendPreimage.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE), EXPECTED_STRING);
    }

    function test_hash_matchesPinnedVector() public {
        assertEq(_hashVector(), EXPECTED_HASH);
    }

    function test_hash_equalsSha256OfLiteralPreimage() public {
        // independent path: the library hash equals sha256 over the literal canonical bytes
        assertEq(_hashVector(), sha256(bytes(EXPECTED_STRING)));
    }

    // ---- the binding: tampering any field changes the hash ---- //

    function test_binding_amountTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT + 1, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE));
    }

    function test_binding_chainTamperChangesHash() public {
        // a witness signed for Chiado (10200) cannot be drawn on Gnosis mainnet (100)
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, 100, CURSOR_ID, NONCE, PAYEE, SAFE));
    }

    function test_binding_cursorIdTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, CHAINID, address(0x1234), NONCE, PAYEE, SAFE));
    }

    function test_binding_nonceTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, CHAINID, CURSOR_ID, bytes32(uint256(1)), PAYEE, SAFE));
    }

    function test_binding_payeeTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, address(0xBEEF), SAFE));
    }

    function test_binding_safeTamperChangesHash() public {
        assertTrue(_hashVector() != SpendPreimage.hash(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, address(0xBEEF)));
    }

    // ---- formatter edge cases ---- //

    function test_dec_zeroRendersZeroNotEmpty() public {
        assertEq(
            SpendPreimage.canonical(0, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE),
            '{"amountWei":"0","chainId":"10200","cursorId":"0x0000000000000000000000000000000000008312","nonce":"0x2fa8e52ccdf87e21b956e1c405f849cb549b528ce16f4c08893e353160748fe1","payee":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045","safeAddress":"0xb7e493e3d226f8fe722cc9916ff164b793af13f4"}'
        );
    }

    function test_addr_rendersLowercaseFromChecksummedInput() public {
        // PAYEE is the EIP-55 checksummed vitalik.eth; output must be lowercase, no checksum
        string memory s = SpendPreimage.canonical(AMOUNT, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE);
        assertTrue(_contains(s, '"payee":"0xd8da6bf26964af9d7eed9e03e53415d37aa96045"'));
    }

    // ---- fuzz: distinct (amount, chain) never collide under sha256 ---- //

    function testFuzz_binding_distinctAmountsDifferentHash(uint256 a, uint256 b) public {
        vm.assume(a != b);
        assertTrue(
            SpendPreimage.hash(a, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE)
                != SpendPreimage.hash(b, CHAINID, CURSOR_ID, NONCE, PAYEE, SAFE)
        );
    }

    function testFuzz_binding_distinctChainsDifferentHash(uint256 c1, uint256 c2) public {
        vm.assume(c1 != c2);
        assertTrue(
            SpendPreimage.hash(AMOUNT, c1, CURSOR_ID, NONCE, PAYEE, SAFE)
                != SpendPreimage.hash(AMOUNT, c2, CURSOR_ID, NONCE, PAYEE, SAFE)
        );
    }

    function _contains(string memory hay, string memory needle) private pure returns (bool) {
        bytes memory h = bytes(hay);
        bytes memory n = bytes(needle);
        if (n.length == 0 || n.length > h.length) return false;
        for (uint256 i = 0; i <= h.length - n.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (h[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
