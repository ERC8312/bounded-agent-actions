// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title ISpendWitnessVerifier
/// @notice The witness-verification seam for a spend-witness budget cursor. A
///         SpendWitnessCursor delegates all signature and schema handling to a
///         verifier implementing this interface, so the cursor itself stays
///         witness-neutral: it meters, it does not parse the witness.
/// @dev    A conforming verifier decodes an opaque witness (e.g.
///         `abi.encode(bytes32 px, bytes32 rx, bytes32 s, bytes preimage)`), checks a
///         recomputable signature (e.g. BIP-340 schnorr over `sha256(preimage)`)
///         against `issuerKey`, and extracts the values the cursor meters against
///         from the SAME signed preimage. Because every returned field is read out of
///         the signed bytes, a `valid == true` return binds them: the amount the
///         cursor meters is the amount that was signed, and the nonce it nullifies is
///         the nonce that was signed.
///
///         "Recomputable" is the load of this interface: a conforming verifier MUST
///         re-derive `valid` from public inputs (re-execution, or a signature checked
///         against a published key), and MUST NOT return `valid` on the strength of an
///         attestation whose validity rests on trusting the attester (a TEE quote, an
///         oracle signature). Gating a draw on an attestation reintroduces a trusted
///         party and voids the trustless property of the composition.
interface ISpendWitnessVerifier {
    /// @param issuerKey The x-only public key the cursor pinned for this envelope.
    /// @param witness   The opaque spend witness.
    /// @return valid    True iff the witness carries a recomputable signature by
    ///                  `issuerKey` over a well-formed spend preimage.
    /// @return amount   The value authorized by the signed preimage (metered by the cursor).
    /// @return cursorId The envelope id the signed preimage authorizes a draw against.
    /// @return nonce    The replay nonce bound in the signed preimage.
    function verifySpend(bytes32 issuerKey, bytes calldata witness)
        external
        view
        returns (bool valid, uint256 amount, bytes32 cursorId, bytes32 nonce);
}
