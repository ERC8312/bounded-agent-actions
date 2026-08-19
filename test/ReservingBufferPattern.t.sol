// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ReservingBudgetCursor} from "../src/ReservingBudgetCursor.sol";
import {IAggregateBudget} from "../src/IAggregateBudget.sol";

/// @notice The standing-buffer batching pattern from CONFIDENTIALITY-CONSIDERATIONS.md,
///         leak 1 (per-transaction timing): per-claim holds republish the payment
///         timeline one ledger over, because a hold consumes headroom the instant it is
///         taken. The batching that actually coarsens the public timeline is ONE hold
///         per node per period sized to the batch envelope — the reservation profile's
///         own reserve and commit, taken once per period instead of once per claim —
///         with per-claim vouchers admitted against it off-record and one net commit at
///         period end.
///
///         What this file proves, and how: 25 payments leave exactly the three pinned
///         meter events (Reserved, Drawn, Committed — selector, emitter, and payload
///         all asserted); conservation holds mid-hold and after settlement; and the
///         pattern's stated COST is demonstrated, not narrated: the over-admission
///         test shows the chain accepting a conformant net while the venue's book has
///         over-admitted past the buffer — in-buffer conformance is verifiable only
///         against the holder's ledger, not the shared record.
contract ReservingBufferPatternTest is Test {
    ReservingBudgetCursor c;

    address issuer = makeAddr("issuer");
    address fleet = makeAddr("fleet");
    address venue = makeAddr("venue");

    bytes32 rootId;
    uint64 leaf;

    uint256 constant CAP = 1000e6;
    uint64 constant PERIOD = 1 days;
    uint64 constant ANCHOR = 1_000_000;
    uint256 constant BUFFER = 300e6;
    uint256 constant VOUCHER = 10e6;
    uint256 constant N_VOUCHERS = 25;

    function setUp() public {
        c = new ReservingBudgetCursor();
        vm.prank(issuer);
        rootId = c.createRoot(fleet, CAP, PERIOD, ANCHOR, bytes32("buffer"));
        vm.prank(fleet);
        leaf = c.delegate(rootId, 0, venue, 0);
        vm.warp(ANCHOR + 1); // start of a period
    }

    function test_standingBuffer_25PaymentsThreeMeterEvents() public {
        vm.recordLogs();

        // one hold for the period's batch envelope, sized to cover the whole period
        vm.prank(venue);
        uint256 claim = c.reserve(rootId, leaf, BUFFER, PERIOD);
        uint64 expiry = uint64(block.timestamp) + PERIOD;

        // conservation holds MID-hold: the buffer consumes headroom at reserve time
        assertEq(c.availableAuthority(rootId), CAP - BUFFER, "buffer must consume headroom immediately");

        // 25 per-claim vouchers admitted OFF-RECORD against the buffer; the admission
        // rule is the venue's book, and nothing here touches the chain
        uint256 admitted;
        for (uint256 i = 0; i < N_VOUCHERS; i++) {
            require(admitted + VOUCHER <= BUFFER, "voucher exceeds buffer");
            admitted += VOUCHER;
        }
        assertEq(admitted, 250e6);

        // one net settlement at period end, inside the same period and before expiry
        vm.warp(ANCHOR + PERIOD - 1);
        vm.prank(venue);
        c.commit(claim, admitted);

        // the whole period is THREE meter events — selector, emitter, payload pinned
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 3, "period should leave exactly three meter events");
        for (uint256 i = 0; i < 3; i++) {
            assertEq(logs[i].emitter, address(c), "foreign emitter");
        }
        assertEq(logs[0].topics[0], ReservingBudgetCursor.Reserved.selector);
        (uint256 rAmt, uint64 rExp) = abi.decode(logs[0].data, (uint256, uint64));
        assertEq(rAmt, BUFFER, "Reserved publishes the buffer total");
        assertEq(rExp, expiry);

        assertEq(logs[1].topics[0], IAggregateBudget.Drawn.selector);
        assertEq(uint256(logs[1].topics[3]), 0, "settles into the reserve period");
        assertEq(abi.decode(logs[1].data, (uint256)), admitted, "Drawn publishes the net");

        assertEq(logs[2].topics[0], ReservingBudgetCursor.Committed.selector);
        (uint256 fin, uint256 ret) = abi.decode(logs[2].data, (uint256, uint256));
        assertEq(fin, admitted, "Committed publishes the net");
        assertEq(ret, BUFFER - admitted, "and the returned remainder");

        // conservation after settlement
        assertEq(c.grossDrawn(rootId, c.currentPeriod(rootId)), admitted);
        assertEq(c.availableAuthority(rootId), CAP - admitted);

        // granularity: the per-voucher amount appears in no topic or data word —
        // only the buffer, the net, and the remainder are public
        assertFalse(_anyWordEquals(logs, VOUCHER), "per-voucher amount leaked");
    }

    function test_cost_overAdmissionInvisibleOnChain() public {
        // the pattern's stated cost, demonstrated: the venue's book over-admits past
        // the buffer (31 x 10e6 = 310e6 > 300e6) — only its OWN require could catch
        // it, and this book has none. The chain then accepts a perfectly conformant
        // net commit. In-buffer conformance is verifiable against the holder's book
        // only; a stranger recomputing from the public record sees nothing wrong.
        vm.prank(venue);
        uint256 claim = c.reserve(rootId, leaf, BUFFER, PERIOD);

        uint256 book;
        for (uint256 i = 0; i < 31; i++) {
            book += VOUCHER; // no admission guard, deliberately
        }
        assertGt(book, BUFFER, "the book has over-admitted");

        vm.warp(ANCHOR + PERIOD - 1);
        vm.prank(venue);
        c.commit(claim, BUFFER); // settles the buffer, not the book

        assertEq(c.grossDrawn(rootId, c.currentPeriod(rootId)), BUFFER, "chain sees a conformant net");
        // the 10e6 gap between book (310e6) and settled (300e6) exists only off-record
    }

    function test_contrast_perClaimModeRepublishesTheTimeline() public {
        // the same three payments settled per-claim, each at its own timestamp: nine
        // meter events carrying per-payment amounts AND per-payment times — this is
        // the timeline leak 1 describes, made literal
        vm.recordLogs();
        vm.startPrank(venue);
        for (uint256 i = 0; i < 3; i++) {
            uint256 id = c.reserve(rootId, leaf, VOUCHER, 1 hours);
            c.commit(id, VOUCHER);
            vm.warp(block.timestamp + 1 hours);
        }
        vm.stopPrank();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 9, "per-claim mode: one Reserved + Drawn + Committed per payment");
        assertTrue(_anyWordEquals(logs, VOUCHER), "per-claim mode publishes each amount");
    }

    function test_bufferRenewsAcrossPeriods() public {
        vm.prank(venue);
        uint256 claim = c.reserve(rootId, leaf, BUFFER, PERIOD);
        vm.warp(ANCHOR + PERIOD - 1);
        vm.prank(venue);
        c.commit(claim, 250e6);

        // next period: fresh meter, fresh buffer
        vm.warp(ANCHOR + PERIOD + 1);
        vm.prank(venue);
        c.reserve(rootId, leaf, BUFFER, PERIOD);
        assertEq(c.availableAuthority(rootId), CAP - BUFFER);
    }

    // ---- helpers ---- //

    function _anyWordEquals(Vm.Log[] memory logs, uint256 value) internal pure returns (bool) {
        for (uint256 i = 0; i < logs.length; i++) {
            bytes memory d = logs[i].data;
            for (uint256 off = 0; off + 32 <= d.length; off += 32) {
                uint256 w;
                assembly {
                    w := mload(add(add(d, 32), off))
                }
                if (w == value) return true;
            }
            for (uint256 t = 0; t < logs[i].topics.length; t++) {
                if (uint256(logs[i].topics[t]) == value) return true;
            }
        }
        return false;
    }
}
