// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";

/// Replays the trustless-ai/recompute-kit aggregate-budget-v0 conformance
/// vectors (vectors sha256 ac6f6efd485e887a7f82140ac5be234643af17efb24506d9cd40e87ecd2bcb85)
/// through the reference cursor. The vectors describe Drawn logs; a conforming
/// registry must (a) admit every draw the pinned (root, period) sum allows,
/// (b) reject every draw that would push the sum past cap, so a non-conserving
/// log is unproducible, and (c) leave spentRoot equal to the vector's expected
/// admittedSum for the pinned slot.
contract AggregateBudgetVectorsTest is Test {
    AggregateBudgetCursor cursor;

    address issuer = address(0x15);
    address rootAgent = address(0xA0);
    address agentA = address(0xA1);
    address agentB = address(0xA2);
    address agentC = address(0xA3);

    uint64 constant PERIOD_LEN = 100;
    uint64 constant ANCHOR = 1000;
    uint256 constant CAP = 2000;

    bytes32 rootId;
    uint64 nodeA;
    uint64 nodeB;
    uint64 nodeC;

    function setUp() public {
        cursor = new AggregateBudgetCursor();
        vm.warp(ANCHOR);
        vm.prank(issuer);
        rootId = cursor.createRoot(rootAgent, CAP, PERIOD_LEN, ANCHOR, bytes32(uint256(1)));
        vm.startPrank(rootAgent);
        nodeA = cursor.delegate(rootId, 0, agentA, 0);
        nodeB = cursor.delegate(rootId, 0, agentB, 0);
        nodeC = cursor.delegate(rootId, 0, agentC, 0);
        vm.stopPrank();
        // vectors pin periodIndex 7
        vm.warp(ANCHOR + 7 * PERIOD_LEN + 1);
        assertEq(cursor.currentPeriod(rootId), 7, "setup: period");
    }

    function _draw(uint64 node, address agent, uint256 amount) internal {
        vm.prank(agent);
        cursor.draw(rootId, node, amount);
    }

    function _drawRoot(uint256 amount) internal {
        vm.prank(rootAgent);
        cursor.draw(rootId, 0, amount);
    }

    // single-edge-within-cap: 1200 from one edge -> sum 1200, conserves
    function test_vector_singleEdgeWithinCap() public {
        _drawRoot(1200);
        assertEq(cursor.spentRoot(rootId, 7), 1200);
    }

    // multi-edge-attributed-within-cap: 600 + 500 + 300 -> 1400, conserves
    function test_vector_multiEdgeAttributedWithinCap() public {
        _draw(nodeA, agentA, 600);
        _draw(nodeB, agentB, 500);
        _draw(nodeC, agentC, 300);
        assertEq(cursor.spentRoot(rootId, 7), 1400);
    }

    // fanout-exceeds-root-cap: 900 + 800 admitted, the 700 that would take the
    // root sum to 2400 > 2000 MUST revert. The non-conserving log in the vector
    // is exactly the log this registry cannot emit.
    function test_vector_fanoutExceedsRootCap_thirdDrawUnproducible() public {
        _draw(nodeA, agentA, 900);
        _draw(nodeB, agentB, 800);
        vm.prank(agentC);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, nodeC, 700);
        assertEq(cursor.spentRoot(rootId, 7), 1700, "meter unchanged by rejected draw");
    }

    // exact-cap-boundary: 1000 + 1000 == cap admits; one more wei reverts
    function test_vector_exactCapBoundary() public {
        _draw(nodeA, agentA, 1000);
        _draw(nodeB, agentB, 1000);
        assertEq(cursor.spentRoot(rootId, 7), 2000);
        vm.prank(agentA);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, nodeA, 1);
    }

    // unadmitted-draws-excluded: 1500 admitted; the 1000 attempt (would be 2500)
    // is the vector's admitted:false entry, and the cursor produces that
    // admitted:false naturally by reverting. Meter shows admitted sum only.
    function test_vector_unadmittedDrawsExcluded() public {
        _draw(nodeA, agentA, 1500);
        vm.prank(agentB);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, nodeB, 1000);
        assertEq(cursor.spentRoot(rootId, 7), 1500);
    }

    // period-index-isolation: p7 draws 800 + 1000 -> p7 slot 1800; p8 activity
    // lands in its own slot and leaves p7 untouched. (The vector's p8 entry of
    // 5000 exceeds this registry's cap, so the reference is stricter than the
    // log format: it also refuses it. Both facts are asserted.)
    function test_vector_periodIndexIsolation() public {
        _draw(nodeA, agentA, 800);
        _draw(nodeB, agentB, 1000);
        assertEq(cursor.spentRoot(rootId, 7), 1800);

        vm.warp(ANCHOR + 8 * PERIOD_LEN + 1);
        assertEq(cursor.currentPeriod(rootId), 8, "period rolled");
        vm.prank(agentA);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, nodeA, 5000);
        _draw(nodeA, agentA, 1999);
        assertEq(cursor.spentRoot(rootId, 8), 1999, "p8 slot independent");
        assertEq(cursor.spentRoot(rootId, 7), 1800, "p7 slot untouched by p8");
    }

    // cross-root-isolation: a second root's draws never touch the pinned root's
    // slot. Root 2 gets a 10000 cap so the vector's 9000 draw is admissible there.
    function test_vector_crossRootIsolation() public {
        _draw(nodeA, agentA, 900);
        _draw(nodeB, agentB, 1000);

        address agent2 = address(0xB1);
        vm.warp(ANCHOR); // create root2, then return to period 7
        vm.prank(issuer);
        bytes32 root2 = cursor.createRoot(agent2, 10000, PERIOD_LEN, ANCHOR, bytes32(uint256(2)));
        vm.warp(ANCHOR + 7 * PERIOD_LEN + 1);
        vm.prank(agent2);
        cursor.draw(root2, 0, 9000);

        assertEq(cursor.spentRoot(rootId, 7), 1900, "pinned root unaffected");
        assertEq(cursor.spentRoot(root2, 7), 9000, "root2 metered separately");
    }
}
