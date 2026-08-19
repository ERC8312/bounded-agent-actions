// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ReservingBudgetCursor} from "../src/ReservingBudgetCursor.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";

/// @notice The reservation extension, and the two attacks that broke the
///         router-local version. Both are regression tests: each fails against
///         the base cursor (holds invisible to the meter) and passes here.
contract ReservingBudgetCursorTest is Test {
    ReservingBudgetCursor c;

    address issuer = makeAddr("issuer");
    address fleet = makeAddr("fleet");
    address opA = makeAddr("opA");
    address opB = makeAddr("opB");

    bytes32 rootId;
    uint64 leafA;
    uint64 leafB;

    uint256 constant CAP = 80e6;

    function setUp() public {
        c = new ReservingBudgetCursor();
        vm.prank(issuer);
        rootId = c.createRoot(fleet, CAP, 0, 0, bytes32("res"));
        vm.startPrank(fleet);
        leafA = c.delegate(rootId, 0, opA, 0);
        leafB = c.delegate(rootId, 0, opB, 0);
        vm.stopPrank();
    }

    // ---------------- the two attacks, now defended ---------------- //

    /// @notice ATTACK 1 (was: sibling draw bounces a reserved claim). The hold
    ///         now consumes conserved headroom, so the sibling draw is refused
    ///         and the hold commits.
    function test_SiblingDrawCannotConsumeHeldAuthority() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 60e6, 1 hours);
        assertEq(c.availableAuthority(rootId), 20e6, "hold consumed headroom immediately");

        vm.prank(fleet);
        vm.expectRevert(ReservingBudgetCursor.RootBoundExceeded.selector);
        c.draw(rootId, 0, 30e6); // the attack: previously succeeded

        vm.prank(fleet);
        c.draw(rootId, 0, 20e6); // what is genuinely free still works

        vm.prank(opA);
        c.commit(id, 60e6);
        assertEq(c.spentRoot(rootId, 0), 80e6, "hold committed in full");
    }

    /// @notice ATTACK 2 (was: two routers double-reserve the same authority).
    ///         Both holds now land in one register, so the second is refused at
    ///         reserve time rather than bouncing at settlement.
    function test_TwoHoldersCannotDoubleReserve() public {
        vm.prank(opA);
        uint256 id1 = c.reserve(rootId, leafA, 60e6, 1 hours);
        vm.prank(opB);
        vm.expectRevert(ReservingBudgetCursor.RootBoundExceeded.selector);
        c.reserve(rootId, leafB, 60e6, 1 hours);

        vm.prank(opB);
        uint256 id2 = c.reserve(rootId, leafB, 20e6, 1 hours); // what fits, fits
        vm.prank(opA);
        c.commit(id1, 60e6);
        vm.prank(opB);
        c.commit(id2, 20e6);
        assertEq(c.spentRoot(rootId, 0), 80e6);
    }

    /// @notice ATTACK 3 (was: revoking a node bounced its outstanding hold).
    ///         Revocation stops NEW authority; it does not revoke headroom
    ///         already consumed by a hold.
    function test_RevocationDoesNotBounceOutstandingHold() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 40e6, 1 hours);
        vm.prank(issuer);
        c.revoke(rootId, leafA);

        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.PathRevoked.selector);
        c.reserve(rootId, leafA, 1e6, 1 hours); // new authority: refused

        vm.prank(opA);
        c.commit(id, 40e6); // existing hold: honoured
        assertEq(c.spentRoot(rootId, 0), 40e6);
    }

    // ---------------- extension semantics ---------------- //

    function test_PartialCommitReturnsRemainder() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 60e6, 1 hours);
        vm.prank(opA);
        c.commit(id, 55e6);
        assertEq(c.spentRoot(rootId, 0), 55e6);
        assertEq(c.reservedRoot(rootId, 0), 0);
        assertEq(c.availableAuthority(rootId), 25e6, "5 of held authority returned");
    }

    function test_ExpiredHoldReleasableByAnyone() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 30e6, 2);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(ReservingBudgetCursor.HoldNotExpired.selector);
        c.release(id);

        vm.warp(block.timestamp + 3);
        vm.prank(makeAddr("stranger"));
        c.release(id);
        assertEq(c.availableAuthority(rootId), CAP);

        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.NotHeld.selector);
        c.commit(id, 30e6);
    }

    function test_CommitAfterExpiryReverts() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 30e6, 2);
        vm.warp(block.timestamp + 3);
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.HoldExpired.selector);
        c.commit(id, 30e6);
    }

    function test_CommitCannotExceedHold() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 30e6, 1 hours);
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.CommitExceedsHold.selector);
        c.commit(id, 30e6 + 1);
    }

    function test_OnlyHolderCommits() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 30e6, 1 hours);
        vm.prank(opB);
        vm.expectRevert(ReservingBudgetCursor.Unauthorized.selector);
        c.commit(id, 30e6);
    }

    /// @notice A card authorisation window routinely outlives a daily cap
    ///         period. The hold consumes the authority of the period it was
    ///         TAKEN in and settles against that same slot whenever it lands.
    function test_HoldMayStraddlePeriodAndSettlesAgainstItsOwnPeriod() public {
        vm.warp(1_000_000);
        vm.prank(issuer);
        bytes32 r2 = c.createRoot(fleet, CAP, 1 days, uint64(block.timestamp), bytes32("per"));
        vm.prank(fleet);
        uint64 leaf = c.delegate(r2, 0, opA, 0);
        vm.prank(opA);
        uint256 id = c.reserve(r2, leaf, 10e6, 3 days);
        assertEq(c.currentPeriod(r2), 0);

        vm.warp(block.timestamp + 2 days); // two periods later
        assertEq(c.currentPeriod(r2), 2);
        vm.prank(opA);
        c.commit(id, 10e6);
        assertEq(c.spentRoot(r2, 0), 10e6, "settles against the period it reserved");
        assertEq(c.spentRoot(r2, 2), 0, "not against the period it landed in");
    }

    function test_HoldTtlIsBounded() public {
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.HoldTtlTooLong.selector);
        c.reserve(rootId, leafA, 10e6, 31 days);
    }

    // ---------------- reversals: money that moves backward ---------------- //

    function test_ReversalCreditsAuthorityBack() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 60e6, 1 hours);
        vm.prank(opA);
        c.commit(id, 60e6);
        assertEq(c.availableAuthority(rootId), 20e6);

        vm.prank(opA);
        c.creditReversal(rootId, leafA, 0, 60e6); // the refund lands
        assertEq(c.availableAuthority(rootId), CAP, "authority restored on reversal");
        assertEq(c.spentRoot(rootId, 0), 0, "net exposure back to zero");
        assertEq(c.grossDrawn(rootId, 0), 60e6, "gross tape still shows the turnover");
    }

    function test_ReversalCannotExceedRealisedSpend() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 30e6, 1 hours);
        vm.prank(opA);
        c.commit(id, 30e6);
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.CreditExceedsSpend.selector);
        c.creditReversal(rootId, leafA, 0, 30e6 + 1); // cannot mint headroom
    }

    function test_ReversalRespectsNodeCap() public {
        vm.prank(fleet);
        uint64 capped = c.delegate(rootId, 0, opA, 25e6);
        vm.prank(opA);
        uint256 id = c.reserve(rootId, capped, 20e6, 1 hours);
        vm.prank(opA);
        c.commit(id, 20e6);
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.CreditExceedsSpend.selector);
        c.creditReversal(rootId, capped, 0, 25e6); // more than this node realised
        vm.prank(opA);
        c.creditReversal(rootId, capped, 0, 20e6);
        vm.prank(opA);
        c.reserve(rootId, capped, 20e6, 1 hours); // sublimit freed too
    }

    function test_OnlyNodeAgentCanCreditReversal() public {
        vm.prank(opA);
        uint256 id = c.reserve(rootId, leafA, 10e6, 1 hours);
        vm.prank(opA);
        c.commit(id, 10e6);
        vm.prank(opB);
        vm.expectRevert(ReservingBudgetCursor.Unauthorized.selector);
        c.creditReversal(rootId, leafA, 0, 10e6);
    }

    function test_NodeCapCountsHoldsToo() public {
        vm.prank(fleet);
        uint64 capped = c.delegate(rootId, 0, opA, 25e6);
        vm.prank(opA);
        c.reserve(rootId, capped, 20e6, 1 hours);
        vm.prank(opA);
        vm.expectRevert(ReservingBudgetCursor.NodeBoundExceeded.selector);
        c.draw(rootId, capped, 10e6);
    }

    /// @notice The base cursor is the control: the same attack succeeds there,
    ///         which is what makes these regression tests bite.
    function test_ControlBaseCursorStillVulnerable() public {
        AggregateBudgetCursor base = new AggregateBudgetCursor();
        vm.prank(issuer);
        bytes32 bRoot = base.createRoot(fleet, CAP, 0, 0, bytes32("base"));
        vm.prank(fleet);
        base.delegate(bRoot, 0, opA, 0);
        // no reservation concept exists: node 0 can consume the whole cap freely
        vm.prank(fleet);
        base.draw(bRoot, 0, 80e6);
        assertEq(base.spentRoot(bRoot, 0), 80e6, "base profile has no hold semantics - hence the extension");
    }
}
