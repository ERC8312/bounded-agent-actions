// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IBoundedAgentAction} from "./IBoundedAgentAction.sol";

/// @title IContestableEnvelope
/// @notice Optional extension that owns the Contested lifecycle. A base registry
///         preserves the Contested enum value but need not support entering or
///         leaving it. `contest` and `resolve` MUST also emit the base
///         EnvelopeStatusChanged event.
/// @dev    Contested is operationally SUSPENSIVE, not descriptive: the base rule
///         rejects advanceCursor on any stored status other than Active, so
///         entering Contested halts advancement and isActive reads false for the
///         duration. An informational review signal therefore MUST NOT ride on
///         lifecycle status, since any stored status other than Active suspends
///         advancement.
interface IContestableEnvelope is IBoundedAgentAction {
    event EnvelopeContested(bytes32 indexed id, address indexed challenger);
    event EnvelopeResolved(bytes32 indexed id, Status outcome);

    /// @notice Active -> Contested. Authorization is implementation-defined (for
    ///         example, a bonded challenger). MUST revert unless status is Active.
    ///         MUST set the resolution deadline.
    function contest(bytes32 id, bytes calldata evidence) external;

    /// @notice Contested -> Active or Contested -> Revoked. MUST be restricted to a
    ///         documented resolver until `resolutionDeadline` has passed, after
    ///         which any caller MAY resolve, with `outcome` restricted to Active.
    ///         MUST revert unless status is Contested and `outcome` is Active or
    ///         Revoked.
    function resolve(bytes32 id, Status outcome, bytes calldata resolution) external;

    /// @notice The instant from which any caller MAY resolve `id`. MUST be set when
    ///         `contest` succeeds and MUST NOT be extended while that contest is
    ///         pending; a subsequent contest sets a fresh deadline. MUST revert
    ///         unless status is Contested.
    /// @dev    An envelope with expiresAt == 0 has no clock of its own, so without
    ///         this a silent resolver leaves it suspended forever and the CHALLENGER
    ///         decides how long the bound stays frozen. The outcome after the
    ///         deadline is Active, not a choosable default: the stall is the
    ///         challenger's, so an unresolved contest returns the envelope to
    ///         service. The window MUST be fixed and documented before any contest
    ///         is raised, since one that never arrives in practice is no exit.
    ///         Not Expired, since that state is terminal and an any-caller edge
    ///         into it would let a metered party contest its own envelope and run
    ///         out the clock to foreclose the verdict.
    function resolutionDeadline(bytes32 id) external view returns (uint64);
}
