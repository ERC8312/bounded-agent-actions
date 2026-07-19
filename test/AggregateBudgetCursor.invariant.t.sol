// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AggregateBudgetCursor} from "../src/AggregateBudgetCursor.sol";

/// @notice Randomized stateful handler. The fuzzer grows the tree, draws from
///         random nodes, revokes random subtrees, and warps time across periods.
///         A ghost ledger records every draw the cursor ADMITTED, per period.
///         The invariant: for every period touched, the cursor's conserved meter
///         equals the ghost sum exactly and never exceeds the root cap — no
///         sequence of delegations, draws, revocations, or rollovers can make
///         the tree realize more than the root bound in any period.
contract AggregateTreeHandler is Test {
    AggregateBudgetCursor public immutable cursor;
    bytes32 public immutable rootId;
    uint256 public immutable cap;
    uint64 public immutable periodLength;
    uint64 public immutable periodAnchor;

    uint64[] public liveNodes; // includes node 0
    mapping(uint64 => address) public agentOf;

    // Ghost ledger: periodIndex => sum of admitted draws.
    mapping(uint64 => uint256) public ghostSpent;
    uint64[] public touchedPeriods;
    mapping(uint64 => bool) internal _touched;

    uint256 public admittedDraws;
    uint256 public rejectedOverCap;

    constructor(AggregateBudgetCursor cursor_, bytes32 rootId_, uint256 cap_, uint64 periodLength_, uint64 anchor_) {
        cursor = cursor_;
        rootId = rootId_;
        cap = cap_;
        periodLength = periodLength_;
        periodAnchor = anchor_;
        liveNodes.push(0);
        agentOf[0] = makeAddr("handler-root-agent");
    }

    function rootAgent() external view returns (address) {
        return agentOf[0];
    }

    // ------------------------------------------------------------------ //
    // Fuzzed actions                                                     //
    // ------------------------------------------------------------------ //

    function delegateNode(uint256 parentSeed, uint256 capSeed) external {
        uint64 parent = liveNodes[parentSeed % liveNodes.length];
        address agent = makeAddr(string(abi.encodePacked("agent-", vm.toString(liveNodes.length))));
        uint256 nodeCap = capSeed % 3 == 0 ? (capSeed % cap) + 1 : 0; // sometimes attenuated

        vm.prank(agentOf[parent]);
        try cursor.delegate(rootId, parent, agent, nodeCap) returns (uint64 nodeId) {
            liveNodes.push(nodeId);
            agentOf[nodeId] = agent;
        } catch {
            // revoked path or depth cap — both legal outcomes for the fuzzer
        }
    }

    function drawFrom(uint256 nodeSeed, uint256 amountSeed) external {
        uint64 node = liveNodes[nodeSeed % liveNodes.length];
        uint256 amount = (amountSeed % (cap / 2)) + 1;
        uint64 period = cursor.currentPeriod(rootId);

        vm.prank(agentOf[node]);
        try cursor.draw(rootId, node, amount) {
            ghostSpent[period] += amount;
            admittedDraws++;
            if (!_touched[period]) {
                _touched[period] = true;
                touchedPeriods.push(period);
            }
        } catch (bytes memory err) {
            if (bytes4(err) == AggregateBudgetCursor.RootBoundExceeded.selector) {
                rejectedOverCap++;
                // The rejected draw MUST actually have been over cap — the meter
                // never rejects an in-budget draw for budget reasons.
                require(ghostSpent[period] + amount > cap, "cursor rejected an in-budget draw as over-cap");
            }
            // PathRevoked / NodeBoundExceeded are legal fuzz outcomes
        }
    }

    function revokeNode(uint256 nodeSeed) external {
        if (liveNodes.length < 2) return;
        uint64 node = liveNodes[(nodeSeed % (liveNodes.length - 1)) + 1]; // never node 0
        (uint64 parent,,,,) = cursor.nodeOf(rootId, node);
        vm.prank(agentOf[parent]);
        try cursor.revoke(rootId, node) {} catch {}
    }

    function warpForward(uint256 timeSeed) external {
        vm.warp(block.timestamp + (timeSeed % (2 * uint256(periodLength))) + 1);
    }

    // ------------------------------------------------------------------ //
    // Views for the invariant                                            //
    // ------------------------------------------------------------------ //

    function touchedPeriodCount() external view returns (uint256) {
        return touchedPeriods.length;
    }
}

contract AggregateBudgetCursorInvariantTest is Test {
    AggregateBudgetCursor internal cursor;
    AggregateTreeHandler internal handler;
    bytes32 internal rootId;

    uint256 internal constant CAP = 250_000e6;
    uint64 internal constant PERIOD = 1 days;

    function setUp() public {
        cursor = new AggregateBudgetCursor();
        uint64 anchor = uint64(block.timestamp);

        // Pre-derive the handler's root-agent address (CREATE address is
        // deterministic only after deployment, so create handler first with a
        // placeholder tree, then the real tree keyed to its agent).
        AggregateTreeHandler probe = new AggregateTreeHandler(cursor, bytes32(0), CAP, PERIOD, anchor);
        address rootAgent = probe.rootAgent();

        rootId = cursor.createRoot(rootAgent, CAP, PERIOD, anchor, bytes32("invariant-tree"));
        handler = new AggregateTreeHandler(cursor, rootId, CAP, PERIOD, anchor);
        // Both handler instances derive the same named root agent address.
        require(handler.rootAgent() == rootAgent, "agent derivation mismatch");

        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = AggregateTreeHandler.delegateNode.selector;
        selectors[1] = AggregateTreeHandler.drawFrom.selector;
        selectors[2] = AggregateTreeHandler.revokeNode.selector;
        selectors[3] = AggregateTreeHandler.warpForward.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice Conservation: in every period the fuzzer touched, the on-chain
    ///         meter equals the ghost sum of admitted draws exactly, and never
    ///         exceeds the cap. Delegation topology, revocation, and rollover
    ///         cannot mint headroom.
    function invariant_TreeSumNeverExceedsCap() public view {
        uint256 periods = handler.touchedPeriodCount();
        for (uint256 i = 0; i < periods; i++) {
            uint64 period = handler.touchedPeriods(i);
            uint256 metered = cursor.spentRoot(rootId, period);
            assertEq(metered, handler.ghostSpent(period), "meter must equal admitted ghost sum");
            assertLe(metered, CAP, "conserved meter must never exceed root cap");
        }
    }
}
