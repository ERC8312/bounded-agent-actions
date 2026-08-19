// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title SpendPreimage
/// @notice Reference reconstruction of the canonical spend-witness preimage and its
///         sha256, byte-for-byte compatible with the off-chain `JSON.stringify` form
///         (keys sorted, no whitespace) that the issuer's BIP-340 signature covers.
/// @dev A cursor rebuilds the preimage from the structured draw fields and requires
///      `sha256(reconstructed) == sigId`. Because the signature is over the same
///      bytes, that equality binds the draw to exactly the amount and chain the issuer
///      signed: a witness signed for one (amount, chain) cannot be advanced at another.
///
///      Canonical value formats:
///        amountWei, chainId        decimal string, no leading zeros ("0" for zero)
///        cursorId, payee, safeAddr lowercase "0x" + 40 hex (NOT EIP-55 checksummed)
///        nonce                     lowercase "0x" + 64 hex
///      Key order is fixed and alphabetical, so the rebuild is one template with six
///      interpolated values, not a general JSON serializer.
///
///      Verified against the pinned vector (Chiado, chainId 10200):
///        sha256 = 0x2775c208604080bcf9e511297ab0fe2ce5ef485b7616ac34acefcb7db2fb9a27
library SpendPreimage {
    bytes16 private constant _HEX = "0123456789abcdef";

    /// @notice Rebuild the canonical preimage string from the six structured fields.
    function canonical(
        uint256 amountWei,
        uint256 chainId,
        address cursorId,
        bytes32 nonce,
        address payee,
        address safeAddress
    ) internal pure returns (string memory) {
        return string.concat(
            '{"amountWei":"',
            _dec(amountWei),
            '","chainId":"',
            _dec(chainId),
            '","cursorId":"',
            _addr(cursorId),
            '","nonce":"',
            _hex32(nonce),
            '","payee":"',
            _addr(payee),
            '","safeAddress":"',
            _addr(safeAddress),
            '"}'
        );
    }

    /// @notice sha256 of the canonical preimage. Equals the issuer's signed `sigId`
    ///         iff the structured fields are exactly what was signed.
    function hash(
        uint256 amountWei,
        uint256 chainId,
        address cursorId,
        bytes32 nonce,
        address payee,
        address safeAddress
    ) internal pure returns (bytes32) {
        return sha256(bytes(canonical(amountWei, chainId, cursorId, nonce, payee, safeAddress)));
    }

    // ------------------------------------------------------------------ //
    // formatters, byte-exact to the off-chain canonical form             //
    // ------------------------------------------------------------------ //

    /// @dev uint256 -> decimal string, no leading zeros, "0" for zero.
    function _dec(uint256 v) private pure returns (string memory) {
        if (v == 0) return "0";
        uint256 d;
        for (uint256 t = v; t != 0; t /= 10) {
            d++;
        }
        bytes memory b = new bytes(d);
        for (uint256 i = d; v != 0; v /= 10) {
            i--;
            b[i] = bytes1(uint8(48 + v % 10));
        }
        return string(b);
    }

    /// @dev address -> "0x" + 40 lowercase hex chars (not checksummed).
    function _addr(address a) private pure returns (string memory) {
        bytes20 raw = bytes20(a);
        bytes memory b = new bytes(42);
        b[0] = "0";
        b[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            b[2 + i * 2] = _HEX[uint8(raw[i]) >> 4];
            b[3 + i * 2] = _HEX[uint8(raw[i]) & 0x0f];
        }
        return string(b);
    }

    /// @dev bytes32 -> "0x" + 64 lowercase hex chars.
    function _hex32(bytes32 v) private pure returns (string memory) {
        bytes memory b = new bytes(66);
        b[0] = "0";
        b[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            b[2 + i * 2] = _HEX[uint8(v[i]) >> 4];
            b[3 + i * 2] = _HEX[uint8(v[i]) & 0x0f];
        }
        return string(b);
    }
}
