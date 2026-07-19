// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAggregateBudget} from "../src/IAggregateBudget.sol";
import {IERC165} from "../src/IERC165.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";

/// @notice Conformance suite for the IAggregateBudget profile. Every test drives
///         the implementation THROUGH THE INTERFACE TYPE, so the suite validates
///         any conformant implementation, not just this reference. The vectors
///         encode the normative MUSTs from the interface NatSpec: the conservation
///         property, the amplification non-conformance boundary, revocation
///         without refund, and ERC-165 advertisement.
///
///         To conformance-test a different implementation, change `deploy()`.
contract AggregateBudgetConformanceTest is Test {
    IAggregateBudget internal agg;

    address internal issuer = makeAddr("issuer");
    address internal rootAgent = makeAddr("rootAgent");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    uint256 internal constant CAP = 100_000e6;
    bytes32 internal rootId;

    function deploy() internal returns (IAggregateBudget) {
        return new AggregateBudgetCursor();
    }

    function setUp() public {
        agg = deploy();
        vm.prank(issuer);
        rootId = agg.createRoot(rootAgent, CAP, 0, 0, bytes32("conformance"));
    }

    // ------------------------------------------------------------------ //
    // ERC-165                                                            //
    // ------------------------------------------------------------------ //

    function test_Conformance_AdvertisesInterfaceIds() public view {
        assertTrue(agg.supportsInterface(type(IAggregateBudget).interfaceId), "MUST advertise IAggregateBudget");
        assertTrue(agg.supportsInterface(type(IERC165).interfaceId), "MUST advertise IERC165");
        assertFalse(agg.supportsInterface(0xffffffff), "MUST NOT advertise the 0xffffffff sentinel");
        assertFalse(agg.supportsInterface(0xdeadbeef), "MUST NOT advertise a random id");
    }

    /// @notice Pins the computed interface id so the ERC text and README can quote
    ///         a stable value. Logged for inspection; asserted non-trivial.
    function test_Conformance_InterfaceIdIsStable() public pure {
        // Pinned so any change to the interface surface is caught as id drift.
        // Recorded in AGGREGATE-BUDGET-PROFILE.md and the reference README.
        assertEq(type(IAggregateBudget).interfaceId, bytes4(0xc7cabe86), "IAggregateBudget id drifted");
    }

    // ------------------------------------------------------------------ //
    // MUST: conservation — the sum across the tree never exceeds the cap  //
    // ------------------------------------------------------------------ //

    /// @notice The core MUST: siblings share ONE root meter. Two children, each
    ///         eligible for the full cap, cannot collectively exceed it.
    function test_Conformance_SiblingsShareOneMeter() public {
        vm.startPrank(rootAgent);
        uint64 a = agg.delegate(rootId, 0, alice, 0);
        uint64 b = agg.delegate(rootId, 0, bob, 0);
        vm.stopPrank();

        vm.prank(alice);
        agg.draw(rootId, a, CAP);

        vm.prank(bob);
        vm.expectRevert(); // conservation: no headroom left tree-wide
        agg.draw(rootId, b, 1);

        assertEq(agg.spentRoot(rootId, 0), CAP, "meter equals realized sum");
        assertEq(agg.remainingRoot(rootId), 0, "no aggregate headroom remains");
    }

    /// @notice Attenuation is NOT conservation: three nodes each capped at the full
    ///         root cap (every pairwise check would pass) still cannot collectively
    ///         exceed it. A conformant meter MUST bound the sum, not just each node.
    function test_Conformance_AttenuationAloneIsInsufficient() public {
        vm.startPrank(rootAgent);
        uint64 a = agg.delegate(rootId, 0, alice, CAP);
        uint64 b = agg.delegate(rootId, 0, bob, CAP);
        uint64 c = agg.delegate(rootId, 0, carol, CAP);
        vm.stopPrank();

        vm.prank(alice);
        agg.draw(rootId, a, 60_000e6);
        vm.prank(bob);
        agg.draw(rootId, b, 40_000e6);
        vm.prank(carol);
        vm.expectRevert();
        agg.draw(rootId, c, 1);
    }

    /// @notice Deep re-delegation does not escape the meter: a depth-3 leaf draw
    ///         meters the single root.
    function test_Conformance_DeepChainMetersRoot() public {
        vm.prank(rootAgent);
        uint64 n1 = agg.delegate(rootId, 0, alice, 0);
        vm.prank(alice);
        uint64 n2 = agg.delegate(rootId, n1, bob, 0);
        vm.prank(bob);
        uint64 n3 = agg.delegate(rootId, n2, carol, 0);

        vm.prank(carol);
        agg.draw(rootId, n3, 40_000e6);
        assertEq(agg.spentRoot(rootId, 0), 40_000e6);
        assertEq(agg.remainingRoot(rootId), CAP - 40_000e6);
    }

    // ------------------------------------------------------------------ //
    // MUST: revocation shrinks headroom, never mints it                   //
    // ------------------------------------------------------------------ //

    function test_Conformance_RevocationDoesNotRefund() public {
        vm.prank(rootAgent);
        uint64 node = agg.delegate(rootId, 0, alice, 0);
        vm.prank(alice);
        agg.draw(rootId, node, 30_000e6);

        vm.prank(issuer);
        agg.revoke(rootId, node);

        // Revoked node cannot draw; prior spend is NOT refunded.
        vm.prank(alice);
        vm.expectRevert();
        agg.draw(rootId, node, 1);

        assertEq(agg.spentRoot(rootId, 0), 30_000e6, "revocation MUST NOT decrement the meter");
        assertEq(agg.remainingRoot(rootId), CAP - 30_000e6);
        assertFalse(agg.isPathActive(rootId, node), "revoked path MUST read inactive");
    }

    // ------------------------------------------------------------------ //
    // MUST: authorization                                                 //
    // ------------------------------------------------------------------ //

    function test_Conformance_OnlyNodeAgentDraws() public {
        vm.prank(rootAgent);
        uint64 node = agg.delegate(rootId, 0, alice, 0);
        vm.prank(bob);
        vm.expectRevert();
        agg.draw(rootId, node, 1);
    }

    function test_Conformance_OnlyParentAgentDelegates() public {
        vm.prank(bob);
        vm.expectRevert();
        agg.delegate(rootId, 0, bob, 0);
    }

    // ------------------------------------------------------------------ //
    // Views expose a coherent, stranger-recomputable tree                 //
    // ------------------------------------------------------------------ //

    function test_Conformance_ViewsAreCoherent() public {
        (address i, uint256 cap, uint64 pl,, uint64 count) = agg.rootOf(rootId);
        assertEq(i, issuer);
        assertEq(cap, CAP);
        assertEq(pl, 0);
        assertEq(count, 1, "only node 0 exists initially");

        vm.prank(rootAgent);
        uint64 node = agg.delegate(rootId, 0, alice, 5_000e6);
        (uint64 parent, uint8 depth, bool revoked, address agent, uint256 nodeCap) = agg.nodeOf(rootId, node);
        assertEq(parent, 0);
        assertEq(depth, 1);
        assertFalse(revoked);
        assertEq(agent, alice);
        assertEq(nodeCap, 5_000e6);
        assertTrue(agg.isPathActive(rootId, node));
        assertEq(agg.currentPeriod(rootId), 0);
    }
}
