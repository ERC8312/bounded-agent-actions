// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title SpendPreimageV2
/// @notice Confidential variant of the canonical spend-witness preimage: the payee is
///         BOUND, not revealed. v1 (`SpendPreimage`) carries `payee` and `safeAddress`
///         in cleartext, so a witness submitted on-chain publishes the counterparty in
///         calldata. v2 replaces both with a single blinded commitment. The issuer's
///         signature still covers exactly one payment destination — a witness signed
///         for one payee cannot be redirected to another — PROVIDED the executing
///         integration verifies the commitment opening against the actual transfer
///         target before funds move. This reference meters draws and gates no
///         execution, so that check is an integration obligation; and unlike v1,
///         where any calldata observer can audit misdirection, under v2 only holders
///         of the opening can.
/// @dev Same canonical discipline as v1: `JSON.stringify` form, keys sorted, no
///      whitespace, sha256 over the exact bytes. A v1 and a v2 digest can never
///      collide: every interpolated value draws from the quote-free alphabet
///      [0-9a-fx], so no value can impersonate a key or delimiter; the shared prefix
///      (amountWei, chainId, cursorId, nonce) is delimited identically in both
///      formats, forcing field-by-field alignment until the fixed key bytes diverge
///      at `"payee"` versus `"payeeCommitment"` — a collision would therefore be a
///      sha256 collision. No further bare-sha256 canonical JSON form may join this
///      family without a pairwise prefix-collision analysis; any future revision
///      should move to explicit domain tags (for example
///      sha256("spend/v3/..." || canonical)) rather than separation by key spelling.
///
///      Canonical value formats (identical to v1 where shared):
///        amountWei, chainId   decimal string, no leading zeros ("0" for zero)
///        cursorId             lowercase "0x" + 40 hex (NOT EIP-55 checksummed)
///        nonce, blinding,
///        payeeCommitment      lowercase "0x" + 64 hex
///
///      The commitment opens as
///        payeeCommitment = sha256('{"blinding":"0x..","payee":"0x..","safeAddress":"0x.."}')
///      and the BLINDING IS LOAD-BEARING: hiding rests entirely on it. The set of
///      plausible payees is small, so an unblinded or predictable hash of
///      (payee, safe) is dictionary-searchable by anyone with a counterparty list.
///      The blinding MUST be 32 bytes from a CSPRNG or a secret-keyed PRF (for
///      example HMAC(k, nonce) under a key that never leaves the agent); it MUST NOT
///      be derived from public or guessable inputs — the nonce alone, any draw
///      field, or a fixed string — and it MUST be fresh per commitment, since a
///      reused blinding links every payment that shares it. A bad blinding produces
///      commitments indistinguishable from good ones; no test can catch it.
///
///      The opening is verified OFF-chain, and commitment equality alone proves
///      nothing. The counterparty MUST (a) verify the issuer's signature over
///      sha256(preimage) against the envelope's pinned issuer key, (b) tie that
///      preimage to the on-chain draw — cursorId matches the envelope, nonce was
///      nullified by it — and only then (c) recompute the commitment from the
///      opening handed over privately and check equality. A signed commitment is not
///      guaranteed to HAVE an opening (an issuer can sign 32 arbitrary bytes), so a
///      payee demands the opening before performing. Nothing here should be called
///      in a transaction with a real payee — that would put the opening in calldata
///      and defeat the construction. On-chain use is the digest path only.
///
///      Scope of the guarantee: a fresh blinding unlinks only the commitment.
///      Amounts, timing, cursorId (every draw on one cursor is trivially linked to
///      that cursor), and the settlement transfer itself remain public and can link
///      or deanonymize draws.
///
///      Pinned vector (same draw as the v1 vector, Chiado, chainId 10200):
///        sha256 = 0xa7dd3012165139d1a887a1f4141b6609d6e2c948acc56d17d423d7548c431049
library SpendPreimageV2 {
    bytes16 private constant _HEX = "0123456789abcdef";

    /// @notice Rebuild the canonical v2 preimage string from the five structured fields.
    function canonical(
        uint256 amountWei,
        uint256 chainId,
        address cursorId,
        bytes32 nonce,
        bytes32 payeeCommitment_
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
            '","payeeCommitment":"',
            _hex32(payeeCommitment_),
            '"}'
        );
    }

    /// @notice sha256 of the canonical v2 preimage. Equals the issuer's signed `sigId`
    ///         iff the structured fields are exactly what was signed.
    function hash(
        uint256 amountWei,
        uint256 chainId,
        address cursorId,
        bytes32 nonce,
        bytes32 payeeCommitment_
    ) internal pure returns (bytes32) {
        return sha256(bytes(canonical(amountWei, chainId, cursorId, nonce, payeeCommitment_)));
    }

    /// @notice Canonical opening string for the payee commitment. Exposed so the
    ///         off-chain side and the tests share one byte-exact definition.
    function commitmentCanonical(address payee, address safeAddress, bytes32 blinding)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            '{"blinding":"',
            _hex32(blinding),
            '","payee":"',
            _addr(payee),
            '","safeAddress":"',
            _addr(safeAddress),
            '"}'
        );
    }

    /// @notice The blinded payee commitment. Pure and view-safe: evaluate off-chain
    ///         (or via eth_call); never pass a real payee through transaction calldata.
    function payeeCommitment(address payee, address safeAddress, bytes32 blinding)
        internal
        pure
        returns (bytes32)
    {
        return sha256(bytes(commitmentCanonical(payee, safeAddress, blinding)));
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
