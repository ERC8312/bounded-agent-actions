// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";

/// @notice The design AggregateBudgetCursor replaces: every delegation edge gets
///         its OWN budget slot, and sub-delegation is guarded only by the
///         attenuation check childCap <= parentCap. This mirrors per-edge keying
///         of the form key = keccak256(issuer, agent). It is included here as the
///         baseline for the sibling-amplification counterexample: attenuation
///         bounds the MAX any leaf draws, not the SUM the tree draws.
contract PerEdgeBudgetMock {
    struct Grant {
        address parentAgent;
        address agent;
        uint256 cap; // this edge's own budget
        uint256 spent; // this edge's own meter — the flaw: no shared slot
        bool exists;
    }

    uint64 public grantCount;
    mapping(uint64 => Grant) public grants;

    error Unauthorized();
    error AttenuationViolated();
    error EdgeBoundExceeded();
    error UnknownGrant();

    /// @dev grantId 0 must be created by the issuer for the root agent.
    function grantRoot(address agent, uint256 cap) external returns (uint64 id) {
        id = grantCount++;
        grants[id] = Grant({parentAgent: msg.sender, agent: agent, cap: cap, spent: 0, exists: true});
    }

    /// @dev Attenuation-only sub-delegation: childCap <= parentCap is checked —
    ///      and a FRESH meter is minted for the child. This is the bug class.
    function subDelegate(uint64 parentId, address agent, uint256 cap) external returns (uint64 id) {
        Grant storage parent = grants[parentId];
        if (!parent.exists) revert UnknownGrant();
        if (msg.sender != parent.agent) revert Unauthorized();
        if (cap > parent.cap) revert AttenuationViolated(); // pairwise, local, cap-only
        id = grantCount++;
        grants[id] = Grant({parentAgent: parent.agent, agent: agent, cap: cap, spent: 0, exists: true});
    }

    function draw(uint64 id, uint256 amount) external {
        Grant storage grant = grants[id];
        if (!grant.exists) revert UnknownGrant();
        if (msg.sender != grant.agent) revert Unauthorized();
        if (grant.spent + amount > grant.cap) revert EdgeBoundExceeded();
        grant.spent += amount;
    }

    function totalRealized() external view returns (uint256 sum) {
        for (uint64 i = 0; i < grantCount; i++) {
            sum += grants[i].spent;
        }
    }
}

contract AggregateBudgetCursorTest is Test {
    AggregateBudgetCursor internal cursor;

    address internal issuer = makeAddr("issuer");
    address internal rootAgent = makeAddr("rootAgent");
    address internal alice = makeAddr("alice"); // sub-agent
    address internal bob = makeAddr("bob"); // sub-agent
    address internal carol = makeAddr("carol"); // sub-sub-agent
    address internal mallory = makeAddr("mallory"); // unauthorized

    uint256 internal constant CAP = 100_000e6; // "USDC"-style units
    bytes32 internal rootId;

    function setUp() public {
        cursor = new AggregateBudgetCursor();
        vm.prank(issuer);
        rootId = cursor.createRoot(rootAgent, CAP, 0, 0, bytes32("tree-1"));
    }

    // ------------------------------------------------------------------ //
    // The counterexample, demonstrated: per-edge metering amplifies      //
    // ------------------------------------------------------------------ //

    /// @notice Baseline bug class: attenuation (childCap <= parentCap) passes for
    ///         every edge, yet the realized SUM is 2x the root cap. Nothing
    ///         reverts. This is the design the aggregate cursor replaces.
    function test_PerEdge_SiblingAmplification_RealizesTwiceTheRootCap() public {
        PerEdgeBudgetMock perEdge = new PerEdgeBudgetMock();

        vm.prank(issuer);
        uint64 root = perEdge.grantRoot(rootAgent, CAP);

        // Both children pass attenuation: CAP <= CAP.
        vm.startPrank(rootAgent);
        uint64 childA = perEdge.subDelegate(root, alice, CAP);
        uint64 childB = perEdge.subDelegate(root, bob, CAP);
        vm.stopPrank();

        vm.prank(alice);
        perEdge.draw(childA, CAP);
        vm.prank(bob);
        perEdge.draw(childB, CAP); // does NOT revert — fresh meter per edge

        assertEq(perEdge.totalRealized(), 2 * CAP, "per-edge design realizes 2x the root bound");
    }

    /// @notice Same tree shape on the aggregate cursor: the second sibling's draw
    ///         reverts because both siblings share ONE root meter.
    function test_Aggregate_SiblingsShareOneMeter_SecondDrawReverts() public {
        vm.startPrank(rootAgent);
        uint64 nodeA = cursor.delegate(rootId, 0, alice, 0);
        uint64 nodeB = cursor.delegate(rootId, 0, bob, 0);
        vm.stopPrank();

        vm.prank(alice);
        cursor.draw(rootId, nodeA, CAP);

        vm.prank(bob);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, nodeB, 1);

        assertEq(cursor.spentRoot(rootId, 0), CAP);
        assertEq(cursor.remainingRoot(rootId), 0);
    }

    // ------------------------------------------------------------------ //
    // Conservation                                                       //
    // ------------------------------------------------------------------ //

    function test_ExactBoundary_DrawToCapOk_OneMoreReverts() public {
        vm.prank(rootAgent);
        uint64 node = cursor.delegate(rootId, 0, alice, 0);

        vm.prank(alice);
        cursor.draw(rootId, node, CAP - 1);
        vm.prank(rootAgent);
        cursor.draw(rootId, 0, 1); // root node spends the last unit

        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, node, 1);
    }

    function test_DeepChain_LeafDrawMetersRoot() public {
        // root -> alice -> bob -> carol (depth 3)
        vm.prank(rootAgent);
        uint64 n1 = cursor.delegate(rootId, 0, alice, 0);
        vm.prank(alice);
        uint64 n2 = cursor.delegate(rootId, n1, bob, 0);
        vm.prank(bob);
        uint64 n3 = cursor.delegate(rootId, n2, carol, 0);

        vm.prank(carol);
        cursor.draw(rootId, n3, 40_000e6);

        assertEq(cursor.spentRoot(rootId, 0), 40_000e6, "leaf draw hits the single root meter");
        assertEq(cursor.remainingRoot(rootId), CAP - 40_000e6);
    }

    /// @notice A mid-tree node fans out to 20 children; the collective never
    ///         exceeds the root headroom no matter how the draws are split.
    function test_MidTreeFanout_CollectiveCappedByRoot() public {
        vm.prank(rootAgent);
        uint64 mid = cursor.delegate(rootId, 0, alice, 0);

        uint64[] memory kids = new uint64[](20);
        for (uint256 i = 0; i < 20; i++) {
            address kidAgent = makeAddr(string(abi.encodePacked("kid", vm.toString(i))));
            vm.prank(alice);
            kids[i] = cursor.delegate(rootId, mid, kidAgent, 0);
        }

        // Each kid tries CAP/10; only 10 succeed, the 11th reverts.
        uint256 slice = CAP / 10;
        for (uint256 i = 0; i < 10; i++) {
            (,,, address agent,) = cursor.nodeOf(rootId, kids[i]);
            vm.prank(agent);
            cursor.draw(rootId, kids[i], slice);
        }
        (,,, address agent11,) = cursor.nodeOf(rootId, kids[10]);
        vm.prank(agent11);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, kids[10], slice);

        assertEq(cursor.spentRoot(rootId, 0), CAP);
    }

    /// @notice Attenuation alone is NOT conservation: three nodes each with
    ///         nodeCap = CAP (every pairwise check would pass) still cannot
    ///         collectively exceed CAP, because the root meter is shared.
    function test_AttenuationAloneInsufficient_ConservationStillHolds() public {
        vm.startPrank(rootAgent);
        uint64 a = cursor.delegate(rootId, 0, alice, CAP);
        uint64 b = cursor.delegate(rootId, 0, bob, CAP);
        uint64 c = cursor.delegate(rootId, 0, carol, CAP);
        vm.stopPrank();
        // Sum of nodeCaps = 3*CAP > CAP. Realizable sum must still be <= CAP.

        vm.prank(alice);
        cursor.draw(rootId, a, 60_000e6);
        vm.prank(bob);
        cursor.draw(rootId, b, 40_000e6);

        vm.prank(carol);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, c, 1);
    }

    /// @notice Same agent ADDRESS under two parents (a "diamond" in address
    ///         space): both node identities still meter the one root slot.
    function test_SameAgentUnderTwoParents_CannotMintBudget() public {
        vm.prank(rootAgent);
        uint64 p1 = cursor.delegate(rootId, 0, alice, 0);
        vm.prank(rootAgent);
        uint64 p2 = cursor.delegate(rootId, 0, bob, 0);

        vm.prank(alice);
        uint64 c1 = cursor.delegate(rootId, p1, carol, 0);
        vm.prank(bob);
        uint64 c2 = cursor.delegate(rootId, p2, carol, 0);

        vm.prank(carol);
        cursor.draw(rootId, c1, CAP);
        vm.prank(carol);
        vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
        cursor.draw(rootId, c2, 1);
    }

    // ------------------------------------------------------------------ //
    // Attenuation (nodeCap) still enforced on top                        //
    // ------------------------------------------------------------------ //

    function test_NodeCapBlocksEvenWithRootHeadroom() public {
        vm.prank(rootAgent);
        uint64 node = cursor.delegate(rootId, 0, alice, 10_000e6);

        vm.prank(alice);
        cursor.draw(rootId, node, 10_000e6);

        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.NodeBoundExceeded.selector);
        cursor.draw(rootId, node, 1); // node cap exhausted; root has headroom

        assertEq(cursor.remainingRoot(rootId), CAP - 10_000e6);
    }

    /// @notice A capped node is a leaf: it cannot delegate. This closes the
    ///         self-delegation escape (a capped node minting an uncapped child to
    ///         draw the full root headroom past its own cap).
    function test_CappedNodeCannotDelegate() public {
        vm.prank(rootAgent);
        uint64 capped = cursor.delegate(rootId, 0, alice, 10_000e6);

        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.CappedNodeCannotDelegate.selector);
        cursor.delegate(rootId, capped, bob, 0);
    }

    /// @notice The escape, demonstrated closed: alice (capped at 10k) can no longer
    ///         route the full cap through a self-minted uncapped child. Her hard
    ///         per-node bound holds even though she controls delegation under herself.
    function test_CapEscapeViaSelfDelegationIsClosed() public {
        vm.prank(rootAgent);
        uint64 capped = cursor.delegate(rootId, 0, alice, 10_000e6);

        // Old hole: alice delegates an uncapped child and draws CAP through it.
        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.CappedNodeCannotDelegate.selector);
        cursor.delegate(rootId, capped, alice, 0);

        // Alice remains bounded by her own cap.
        vm.prank(alice);
        cursor.draw(rootId, capped, 10_000e6);
        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.NodeBoundExceeded.selector);
        cursor.draw(rootId, capped, 1);
    }

    /// @notice Uncapped backbone nodes still delegate normally (the delegating
    ///         backbone / capped-leaf split).
    function test_UncappedNodeStillDelegates() public {
        vm.prank(rootAgent);
        uint64 backbone = cursor.delegate(rootId, 0, alice, 0); // uncapped
        vm.prank(alice);
        uint64 leaf = cursor.delegate(rootId, backbone, bob, 5_000e6); // capped leaf
        vm.prank(bob);
        cursor.draw(rootId, leaf, 5_000e6);
        assertEq(cursor.spentRoot(rootId, 0), 5_000e6);
    }

    // ------------------------------------------------------------------ //
    // Revocation                                                         //
    // ------------------------------------------------------------------ //

    function test_RevokedNodeCannotDraw_AndSpendIsNotRefunded() public {
        vm.prank(rootAgent);
        uint64 node = cursor.delegate(rootId, 0, alice, 0);

        vm.prank(alice);
        cursor.draw(rootId, node, 30_000e6);

        vm.prank(issuer);
        cursor.revoke(rootId, node);

        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.PathRevoked.selector);
        cursor.draw(rootId, node, 1);

        // No refund minting: realized spend stays realized.
        assertEq(cursor.spentRoot(rootId, 0), 30_000e6);
        assertEq(cursor.remainingRoot(rootId), CAP - 30_000e6);
    }

    function test_AncestorRevocationBlocksWholeSubtree() public {
        vm.prank(rootAgent);
        uint64 mid = cursor.delegate(rootId, 0, alice, 0);
        vm.prank(alice);
        uint64 leaf = cursor.delegate(rootId, mid, bob, 0);

        // Parent agent (rootAgent) revokes the mid node.
        vm.prank(rootAgent);
        cursor.revoke(rootId, mid);

        vm.prank(bob);
        vm.expectRevert(AggregateBudgetCursor.PathRevoked.selector);
        cursor.draw(rootId, leaf, 1);

        // And the revoked mid cannot extend the tree either.
        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.PathRevoked.selector);
        cursor.delegate(rootId, mid, carol, 0);
    }

    function test_RevokeAuthz() public {
        vm.prank(rootAgent);
        uint64 node = cursor.delegate(rootId, 0, alice, 0);

        vm.prank(mallory);
        vm.expectRevert(AggregateBudgetCursor.Unauthorized.selector);
        cursor.revoke(rootId, node);

        // The node's own agent cannot self-revoke under this policy either
        // (only issuer or parent agent).
        vm.prank(alice);
        vm.expectRevert(AggregateBudgetCursor.Unauthorized.selector);
        cursor.revoke(rootId, node);
    }

    // ------------------------------------------------------------------ //
    // Periods                                                            //
    // ------------------------------------------------------------------ //

    function test_PeriodRollover_ResetsMeter() public {
        uint64 anchor = uint64(block.timestamp);
        vm.prank(issuer);
        bytes32 periodicRoot = cursor.createRoot(rootAgent, CAP, 1 days, anchor, bytes32("periodic"));

        vm.prank(rootAgent);
        uint64 node = cursor.delegate(periodicRoot, 0, alice, 0);

        vm.prank(alice);
        cursor.draw(periodicRoot, node, CAP);
        assertEq(cursor.remainingRoot(periodicRoot), 0);

        vm.warp(anchor + 1 days); // next period
        assertEq(cursor.currentPeriod(periodicRoot), 1);
        assertEq(cursor.remainingRoot(periodicRoot), CAP, "fresh period, fresh conserved meter");

        vm.prank(alice);
        cursor.draw(periodicRoot, node, CAP); // fine in period 1

        // Period 0's meter is untouched history.
        assertEq(cursor.spentRoot(periodicRoot, 0), CAP);
        assertEq(cursor.spentRoot(periodicRoot, 1), CAP);
    }

    // ------------------------------------------------------------------ //
    // AuthZ / plumbing                                                   //
    // ------------------------------------------------------------------ //

    function test_OnlyNodeAgentDraws() public {
        vm.prank(rootAgent);
        uint64 node = cursor.delegate(rootId, 0, alice, 0);
        vm.prank(mallory);
        vm.expectRevert(AggregateBudgetCursor.Unauthorized.selector);
        cursor.draw(rootId, node, 1);
    }

    function test_OnlyParentAgentDelegates() public {
        vm.prank(mallory);
        vm.expectRevert(AggregateBudgetCursor.Unauthorized.selector);
        cursor.delegate(rootId, 0, mallory, 0);
    }

    function test_DepthCapEnforced() public {
        uint64 parent = 0;
        address prevAgent = rootAgent;
        // Build to MAX_DEPTH - 1 children deep; the next delegate must revert.
        for (uint256 i = 1; i < cursor.MAX_DEPTH(); i++) {
            address next = makeAddr(string(abi.encodePacked("chain", vm.toString(i))));
            vm.prank(prevAgent);
            parent = cursor.delegate(rootId, parent, next, 0);
            prevAgent = next;
        }
        vm.prank(prevAgent);
        vm.expectRevert(AggregateBudgetCursor.DepthExceeded.selector);
        cursor.delegate(rootId, parent, makeAddr("one-too-deep"), 0);
    }

    function test_UnknownRootAndNodeRevert() public {
        vm.expectRevert(AggregateBudgetCursor.UnknownRoot.selector);
        cursor.draw(bytes32("nope"), 0, 1);

        vm.prank(rootAgent);
        vm.expectRevert(AggregateBudgetCursor.UnknownNode.selector);
        cursor.draw(rootId, 99, 1);
    }

    function test_ZeroAmountReverts() public {
        vm.prank(rootAgent);
        vm.expectRevert(AggregateBudgetCursor.ZeroAmount.selector);
        cursor.draw(rootId, 0, 0);
    }

    function test_DuplicateRootReverts() public {
        vm.prank(issuer);
        vm.expectRevert(AggregateBudgetCursor.RootExists.selector);
        cursor.createRoot(rootAgent, CAP, 0, 0, bytes32("tree-1"));
    }

    // ------------------------------------------------------------------ //
    // Fuzz: random split of draws across a random fan-out                //
    // ------------------------------------------------------------------ //

    /// @notice For any fan-out and any draw sequence, the realized sum equals the
    ///         root meter and never exceeds the cap.
    function testFuzz_RandomFanoutAndDraws_SumNeverExceedsCap(uint256 seed) public {
        uint256 fanout = 1 + (seed % 8);
        uint64[] memory nodes = new uint64[](fanout);
        for (uint256 i = 0; i < fanout; i++) {
            address agent = makeAddr(string(abi.encodePacked("fuzz", vm.toString(i))));
            vm.prank(rootAgent);
            nodes[i] = cursor.delegate(rootId, 0, agent, 0);
        }

        uint256 realized;
        for (uint256 step = 0; step < 32; step++) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            uint64 node = nodes[seed % fanout];
            uint256 amount = 1 + (seed % (CAP / 4));
            (,,, address agent,) = cursor.nodeOf(rootId, node);
            vm.prank(agent);
            if (realized + amount > CAP) {
                vm.expectRevert(AggregateBudgetCursor.RootBoundExceeded.selector);
                cursor.draw(rootId, node, amount);
            } else {
                cursor.draw(rootId, node, amount);
                realized += amount;
            }
        }

        assertLe(realized, CAP, "realized sum bounded by cap");
        assertEq(cursor.spentRoot(rootId, 0), realized, "meter equals realized sum exactly");
    }
}
