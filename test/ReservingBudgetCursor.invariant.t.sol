// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ReservingBudgetCursor} from "../src/ReservingBudgetCursor.sol";

/// @notice Stateful suite rebuilt to exercise the interleavings the previous
///         handler could not see: MULTIPLE holders, DIRECT sibling draws, and
///         REVOCATION — the three routes by which a hold previously bounced.
contract ReservingHandler is Test {
    ReservingBudgetCursor public c;
    bytes32 public rootId;
    uint256 public constant CAP = 500e6;

    address public issuer = address(0xA11CE);
    address public fleet = address(0xF1EE7);
    address[3] public ops = [address(0x0B01), address(0x0B02), address(0x0B03)];
    uint64[3] public leaves;

    uint256[] public liveClaims;
    uint256 public commitsAttempted;
    uint256 public commitsSucceeded;

    constructor() {
        c = new ReservingBudgetCursor();
        vm.prank(issuer);
        rootId = c.createRoot(fleet, CAP, 0, 0, bytes32("inv"));
        vm.startPrank(fleet);
        for (uint256 i = 0; i < 3; i++) leaves[i] = c.delegate(rootId, 0, ops[i], 0);
        vm.stopPrank();
    }

    function reserve(uint256 seed, uint256 amount) external {
        uint256 i = seed % 3;
        amount = bound(amount, 1, 200e6);
        vm.prank(ops[i]);
        try c.reserve(rootId, leaves[i], amount, 1 hours) returns (uint256 id) {
            liveClaims.push(id);
        } catch { /* refused on authority or revoked path — correct */ }
    }

    /// @notice A HELD claim must always commit. Not wrapped in try/catch: a
    ///         revert here fails the run, which is the whole point.
    function commit(uint256 seed) external {
        if (liveClaims.length == 0) return;
        uint256 idx = seed % liveClaims.length;
        uint256 id = liveClaims[idx];
        (,,,, uint256 amount,, ReservingBudgetCursor.ClaimStatus status) = c.claims(id);
        if (status != ReservingBudgetCursor.ClaimStatus.Held) return;
        (,,,,,address holder,) = c.claims(id);
        uint256 finalAmt = bound(seed >> 8, 1, amount);
        commitsAttempted++;
        vm.prank(holder);
        c.commit(id, finalAmt);
        commitsSucceeded++;
        liveClaims[idx] = liveClaims[liveClaims.length - 1];
        liveClaims.pop();
    }

    function release(uint256 seed) external {
        if (liveClaims.length == 0) return;
        uint256 idx = seed % liveClaims.length;
        uint256 id = liveClaims[idx];
        (,,,,,address holder, ReservingBudgetCursor.ClaimStatus status) = c.claims(id);
        if (status != ReservingBudgetCursor.ClaimStatus.Held) return;
        vm.prank(holder);
        c.release(id);
        liveClaims[idx] = liveClaims[liveClaims.length - 1];
        liveClaims.pop();
    }

    /// @notice THE attack the old handler never ran: a sibling drawing directly
    ///         on the conserved register while holds are outstanding.
    function siblingDraw(uint256 seed, uint256 amount) external {
        amount = bound(amount, 1, 200e6);
        if (seed % 2 == 0) {
            vm.prank(fleet);
            try c.draw(rootId, 0, amount) {} catch {}
        } else {
            uint256 i = seed % 3;
            vm.prank(ops[i]);
            try c.draw(rootId, leaves[i], amount) {} catch {}
        }
    }

    /// @notice Reversals in the mix: money moving backward must never mint
    ///         headroom a node did not realise, and must never break the cap.
    function reverseSome(uint256 seed, uint256 amount) external {
        uint256 i = seed % 3;
        amount = bound(amount, 1, 120e6);
        vm.prank(ops[i]);
        try c.creditReversal(rootId, leaves[i], 0, amount) {} catch {}
    }

    /// @notice The second attack the old handler never ran.
    function revokeLeaf(uint256 seed) external {
        uint256 i = seed % 3;
        vm.prank(issuer);
        try c.revoke(rootId, leaves[i]) {} catch {}
    }
}

contract ReservingBudgetCursorInvariantTest is Test {
    ReservingHandler h;

    function setUp() public {
        h = new ReservingHandler();
        targetContract(address(h));
    }

    /// @notice Conservation, extended: realized spend plus every outstanding
    ///         hold stays within the cap. This is what makes a hold a promise.
    function invariant_SpendPlusHoldsWithinCap() public view {
        assertLe(
            h.c().spentRoot(h.rootId(), 0) + h.c().reservedRoot(h.rootId(), 0),
            h.CAP(),
            "realized spend plus outstanding holds exceeded the root cap"
        );
    }

    /// @notice Every commit attempted on a live hold succeeded. Previously
    ///         vacuous; now the handler can actually produce the bounce.
    function invariant_EveryHeldClaimCommits() public view {
        assertEq(h.commitsAttempted(), h.commitsSucceeded(), "a held claim failed to commit");
    }

    /// @notice The base profile's own property survives the extension.
    function invariant_RealizedSpendWithinCap() public view {
        assertLe(h.c().spentRoot(h.rootId(), 0), h.CAP(), "realized spend exceeded the cap");
    }

    /// @notice Reversals net exposure down; they never credit back more than
    ///         was drawn, so net can never exceed gross.
    function invariant_NetNeverExceedsGross() public view {
        assertLe(
            h.c().spentRoot(h.rootId(), 0),
            h.c().grossDrawn(h.rootId(), 0),
            "net exposure exceeded gross turnover - a reversal minted headroom"
        );
    }
}
