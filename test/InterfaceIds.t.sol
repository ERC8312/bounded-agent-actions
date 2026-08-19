// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IBoundedAgentAction} from "../src/IBoundedAgentAction.sol";
import {IBudgetSubstrate} from "../src/IBudgetSubstrate.sol";
import {IContestableEnvelope} from "../src/IContestableEnvelope.sol";
import {IAggregateBudget} from "../src/IAggregateBudget.sol";

/// @notice The ERC-165 identifiers the spec publishes are stated to be computed
///         from this reference. This asserts that, so the two cannot drift.
contract InterfaceIdsTest is Test {
    function test_publishedInterfaceIds() public pure {
        assertEq(type(IBoundedAgentAction).interfaceId, bytes4(0x3985961d), "IBoundedAgentAction");
        assertEq(type(IBudgetSubstrate).interfaceId, bytes4(0x021ca455), "IBudgetSubstrate");
        assertEq(type(IContestableEnvelope).interfaceId, bytes4(0xd79116b5), "IContestableEnvelope");
        assertEq(type(IAggregateBudget).interfaceId, bytes4(0xc7cabe86), "IAggregateBudget");
    }
}
