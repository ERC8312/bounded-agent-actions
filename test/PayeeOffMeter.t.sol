// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";
import {ReservingBudgetCursor} from "../src/ReservingBudgetCursor.sol";
import {IAggregateBudget} from "../src/IAggregateBudget.sol";

/// @notice Pins the confidentiality table row "payee, memo, purpose — never on the
///         meter": across a full metering lifecycle on both reference cursors, the
///         counterparty being paid appears in no event topic and no event data —
///         neither as raw bytes nor as a keccak256/sha256 image of its address (a
///         hashed payee in an indexed topic would be dictionary-linkable by anyone
///         with a counterparty list, which is the same failure).
///
///         Scope, stated: the claim is payee-off-meter, and it assumes the payee is
///         not itself a node agent. Node AGENTS are on the meter by design — that is
///         attribution, the doc's leak 3 — and the companion test below pins that
///         admitted disclosure so nobody mistakes this file for an anonymity claim.
///         In venue-as-node deployments the counterparty's address IS the node agent.
///
///         This is an interface-freeze tripwire with the surface pinned: the exact
///         event count and the exact selector set are asserted, so a new event, a
///         dropped event, or a payee-bearing variant of an existing one fails the
///         test even before any payee flows. The detector itself is proven live by
///         the decoy self-tests.
contract PayeeOffMeterTest is Test {
    AggregateBudgetCursor agg;
    ReservingBudgetCursor res;

    address issuer = makeAddr("issuer");
    address fleet = makeAddr("fleet");
    address operator = makeAddr("operator");

    // the counterparty the flow settles to, off-meter; its bytes must never surface
    address constant PAYEE = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;

    bytes32 aggRoot;
    bytes32 resRoot;
    uint64 aggLeaf;
    uint64 resLeaf;
    uint64 aggScratch;
    uint64 resScratch;

    event Decoy(address indexed payee, uint256 amount);
    event UnindexedDecoy(address payee);

    function setUp() public {
        agg = new AggregateBudgetCursor();
        res = new ReservingBudgetCursor();
        vm.startPrank(issuer);
        aggRoot = agg.createRoot(fleet, 100e6, 0, 0, bytes32("agg"));
        resRoot = res.createRoot(fleet, 100e6, 0, 0, bytes32("res"));
        vm.stopPrank();
        vm.startPrank(fleet);
        aggLeaf = agg.delegate(aggRoot, 0, operator, 0);
        resLeaf = res.delegate(resRoot, 0, operator, 0);
        aggScratch = agg.delegate(aggRoot, 0, makeAddr("scratchA"), 0);
        resScratch = res.delegate(resRoot, 0, makeAddr("scratchR"), 0);
        vm.stopPrank();
    }

    function test_payeeNeverInMeterLogs() public {
        vm.recordLogs();

        // aggregate profile: plain draws
        vm.startPrank(operator);
        agg.draw(aggRoot, aggLeaf, 10e6);
        agg.draw(aggRoot, aggLeaf, 5e6);

        // reservation profile: full lifecycle — hold, partial capture, release, reversal
        uint256 held = res.reserve(resRoot, resLeaf, 40e6, 1 hours);
        res.commit(held, 30e6);
        uint256 dropped = res.reserve(resRoot, resLeaf, 20e6, 1 hours);
        res.release(dropped);
        res.creditReversal(resRoot, resLeaf, 0, 5e6);
        vm.stopPrank();

        // revocation, on both cursors
        vm.startPrank(fleet);
        agg.revoke(aggRoot, aggScratch);
        res.revoke(resRoot, resScratch);
        vm.stopPrank();

        Vm.Log[] memory logs = vm.getRecordedLogs();

        // surface freeze: exactly these events, from exactly these emitters
        assertEq(logs.length, 10, "meter surface changed: expected 10 lifecycle events");
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(logs[i].emitter == address(agg) || logs[i].emitter == address(res), "foreign emitter");
            assertTrue(_allowedSelector(logs[i].topics[0]), "unknown meter event");
        }

        // the claim: no payee, raw or hashed, in any topic or data
        assertFalse(_logsContain(logs, abi.encodePacked(PAYEE)), "raw payee bytes on the meter");
        assertFalse(_logsContain(logs, abi.encodePacked(keccak256(abi.encodePacked(PAYEE)))), "keccak(payee) on the meter");
        assertFalse(_logsContain(logs, abi.encodePacked(keccak256(abi.encode(PAYEE)))), "keccak(padded payee) on the meter");
        assertFalse(_logsContain(logs, abi.encodePacked(sha256(abi.encodePacked(PAYEE)))), "sha256(payee) on the meter");
        assertFalse(_logsContain(logs, abi.encodePacked(sha256(abi.encode(PAYEE)))), "sha256(padded payee) on the meter");
    }

    function test_attributionIsOnTheMeter_byDesign() public {
        // the admitted disclosure, pinned so the claim above stays scoped: a node
        // AGENT's address is public in NodeDelegated data — attribution (leak 3),
        // not payee. If the counterparty is made a node, it is on the meter.
        address venue = makeAddr("venueAsNode");
        vm.recordLogs();
        vm.prank(fleet);
        agg.delegate(aggRoot, 0, venue, 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_logsContain(logs, abi.encodePacked(venue)), "node agent should be visible: attribution is public");
    }

    function test_detectorSelfTest_decoyIsCaught() public {
        // positive control: an event that DOES carry the payee (indexed, so it lands
        // in a topic) is found by the same scanner — a pass above is a real absence
        vm.recordLogs();
        emit Decoy(PAYEE, 1);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_logsContain(logs, abi.encodePacked(PAYEE)), "detector missed payee in a topic");
    }

    function test_detectorSelfTest_decoyInDataIsCaught() public {
        // and in unindexed data
        vm.recordLogs();
        emit UnindexedDecoy(PAYEE);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_logsContain(logs, abi.encodePacked(PAYEE)), "detector missed payee in data");
    }

    // ---- allowed meter surface ---- //

    function _allowedSelector(bytes32 sel) internal pure returns (bool) {
        return sel == IAggregateBudget.Drawn.selector || sel == IAggregateBudget.NodeRevoked.selector
            || sel == ReservingBudgetCursor.Reserved.selector || sel == ReservingBudgetCursor.Committed.selector
            || sel == ReservingBudgetCursor.ReleasedHold.selector || sel == ReservingBudgetCursor.Reversed.selector;
    }

    // ---- scanner: byte needle over every topic and every data byte ---- //

    function _logsContain(Vm.Log[] memory logs, bytes memory pat) internal pure returns (bool) {
        for (uint256 i = 0; i < logs.length; i++) {
            bytes memory buf = logs[i].data;
            for (uint256 t = 0; t < logs[i].topics.length; t++) {
                buf = abi.encodePacked(buf, logs[i].topics[t]);
            }
            if (_contains(buf, pat)) return true;
        }
        return false;
    }

    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        if (needle.length == 0 || needle.length > haystack.length) return false;
        for (uint256 i = 0; i + needle.length <= haystack.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
