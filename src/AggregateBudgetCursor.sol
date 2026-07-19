// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IAggregateBudget} from "./IAggregateBudget.sol";
import {IERC165} from "./IERC165.sol";

/// @title AggregateBudgetCursor
/// @notice Reference implementation of the ERC-8312 aggregate-budget profile: a
///         single conserved spend meter per (root, period) shared by an entire
///         delegation tree. Every draw by any node checks-and-decrements the SAME
///         root meter, so the realized sum of draws across the whole tree can
///         never exceed the root cap — regardless of fan-out, depth, or
///         re-delegation.
///
///         This is deliberately distinct from per-edge metering (each delegation
///         edge carrying its own budget slot). Per-edge attenuation bounds the
///         MAXIMUM any single leaf can draw; it does not bound the SUM: a parent
///         with cap B can mint two children of cap B each, and the pair can
///         realize 2B. See PerEdgeBudgetMock and the paired tests for the
///         counterexample. Here, per-node caps still provide attenuation, and the
///         root meter provides conservation; the two are independent checks.
///
/// @dev    Scope, stated exactly:
///         - Safety only, single chain. The Σ ≤ cap invariant is enforced by the
///           serialized check-then-decrement on one storage slot under EVM
///           transaction serialization. No claim is made about aggregation across
///           chains (which would require cross-chain atomic decrement), and no
///           reservation/refund mechanism is included (draws are final within a
///           period; liveness engineering is a substrate concern, not part of the
///           safety reference).
///         - Like the other references in this repository, this contract meters;
///           it does not move assets and gates no execution path by itself.
///           Non-bypassability (routing every spend through the meter) is a
///           substrate obligation.
///         - Known limitation (by design, not a bug): the ONLY conserved meter is
///           the global root. `nodeCap` attenuates a single node's own draws; it
///           does NOT ring-fence a sub-budget for that node's subtree, and a
///           single unattenuated leaf can draw the whole root cap and starve its
///           siblings for the period. Per-subtree aggregate meters and a
///           reserve/commit/refund extension for liveness are deferred to a
///           normative profile; the core here is the minimal proven safety
///           primitive (Sigma of draws <= root cap), nothing more.
contract AggregateBudgetCursor is IAggregateBudget {
    // --------------------------------------------------------------------- //
    // Storage                                                               //
    // --------------------------------------------------------------------- //

    struct Root {
        address issuer; // principal who created the tree and owns revocation
        uint256 cap; // conserved budget per period, shared by the whole tree
        uint64 periodLength; // 0 = single non-resetting period
        uint64 periodAnchor; // period 0 starts here when periodLength != 0
        uint64 nodeCount; // next nodeId; node 0 is the root agent's node
        bool exists;
    }

    struct Node {
        uint64 parent; // parent nodeId; node 0 is its own parent sentinel
        uint8 depth; // root node = 0; delegate() enforces depth < MAX_DEPTH
        bool revoked;
        bool exists;
        address agent; // the key that may draw through / delegate under this node
        uint256 nodeCap; // per-period attenuation cap for THIS node; 0 = no cap
    }

    /// @notice Maximum delegation depth. Bounds the ancestor walk on draw().
    uint8 public constant MAX_DEPTH = 16;

    mapping(bytes32 => Root) private _roots;
    mapping(bytes32 => mapping(uint64 => Node)) private _nodes;

    /// @notice THE conserved meter: rootId => periodIndex => realized spend of the
    ///         entire tree. Conservation is exactly the statement that draw()
    ///         admits an amount only if spentRoot + amount <= cap on THIS slot.
    mapping(bytes32 => mapping(uint64 => uint256)) public spentRoot;

    /// @notice Per-node attenuation meter: rootId => nodeId => periodIndex => spend.
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => uint256))) public spentNode;

    // --------------------------------------------------------------------- //
    // Errors (events are inherited from IAggregateBudget)                    //
    // --------------------------------------------------------------------- //

    error RootExists();
    error UnknownRoot();
    error UnknownNode();
    error ZeroAgent();
    error ZeroCap();
    error BadAnchor();
    error Unauthorized();
    error DepthExceeded();
    error CappedNodeCannotDelegate();
    error PathRevoked();
    error ZeroAmount();
    error RootBoundExceeded();
    error NodeBoundExceeded();
    error PeriodNotStarted();

    // --------------------------------------------------------------------- //
    // Root + tree construction                                              //
    // --------------------------------------------------------------------- //

    /// @notice Deterministic root id; the issuer is part of the id so two trees by
    ///         different principals never collide.
    function computeRootId(address issuer, address agent, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), issuer, agent, salt));
    }

    /// @notice Create a delegation tree: a conserved budget of `cap` per period,
    ///         rooted at `agent` (node 0). msg.sender is the issuer/principal.
    function createRoot(address agent, uint256 cap, uint64 periodLength, uint64 periodAnchor, bytes32 salt)
        external
        returns (bytes32 rootId)
    {
        if (agent == address(0)) revert ZeroAgent();
        if (cap == 0) revert ZeroCap();
        if (periodLength != 0 && periodAnchor == 0) revert BadAnchor();

        rootId = computeRootId(msg.sender, agent, salt);
        Root storage root = _roots[rootId];
        if (root.exists) revert RootExists();

        root.issuer = msg.sender;
        root.cap = cap;
        root.periodLength = periodLength;
        root.periodAnchor = periodAnchor;
        root.nodeCount = 1;
        root.exists = true;

        Node storage n0 = _nodes[rootId][0];
        n0.parent = 0;
        n0.depth = 0;
        n0.agent = agent;
        n0.nodeCap = 0; // the root node is bounded by the root cap alone
        n0.exists = true;

        emit RootCreated(rootId, msg.sender, agent, cap, periodLength);
    }

    /// @notice Delegate a child node under `parentId`. Only the parent node's agent
    ///         may extend the tree beneath itself, and only while its own path to
    ///         the root is unrevoked. The child never receives a fresh budget: it
    ///         shares the root meter. `nodeCap` (optional, 0 = none) attenuates the
    ///         child's own per-period draw on top of the shared meter.
    /// @dev    A CAPPED node (nodeCap != 0) is a leaf: it MAY NOT delegate. Without
    ///         this, a node capped at X could delegate itself an uncapped child and
    ///         draw the full root headroom, defeating the cap. Restricting
    ///         delegation to uncapped backbone nodes makes nodeCap a sound hard
    ///         per-node bound (the flat vendor/variant tree shape). Ring-fencing a
    ///         cap across a delegating subtree needs a per-subtree meter, out of
    ///         scope for this reference (see contract-level Known limitation).
    function delegate(bytes32 rootId, uint64 parentId, address agent, uint256 nodeCap)
        external
        returns (uint64 nodeId)
    {
        Root storage root = _rootOf(rootId);
        Node storage parent = _nodeOf(rootId, parentId);
        if (agent == address(0)) revert ZeroAgent();
        if (msg.sender != parent.agent) revert Unauthorized();
        if (parent.nodeCap != 0) revert CappedNodeCannotDelegate();
        _requirePathActive(rootId, parentId);
        if (parent.depth + 1 >= MAX_DEPTH) revert DepthExceeded();

        nodeId = root.nodeCount;
        root.nodeCount = nodeId + 1;

        Node storage child = _nodes[rootId][nodeId];
        child.parent = parentId;
        child.depth = parent.depth + 1;
        child.agent = agent;
        child.nodeCap = nodeCap;
        child.exists = true;

        emit NodeDelegated(rootId, parentId, nodeId, agent, nodeCap);
    }

    // --------------------------------------------------------------------- //
    // Draw — the conservation checkpoint                                    //
    // --------------------------------------------------------------------- //

    /// @notice Meter a spend of `amount` by `nodeId`. Admitted only if (i) the
    ///         caller is the node's agent, (ii) every node on the path to the root
    ///         is unrevoked, (iii) the node's own attenuation cap (if any) is
    ///         respected, and (iv) — conservation — the SINGLE root meter stays
    ///         within the root cap. Checks-effects; no external calls.
    function draw(bytes32 rootId, uint64 nodeId, uint256 amount) external {
        Root storage root = _rootOf(rootId);
        Node storage node = _nodeOf(rootId, nodeId);
        if (amount == 0) revert ZeroAmount();
        if (msg.sender != node.agent) revert Unauthorized();
        _requirePathActive(rootId, nodeId);

        uint64 period = _periodIndex(root);

        if (node.nodeCap != 0) {
            uint256 ns = spentNode[rootId][nodeId][period];
            if (ns + amount > node.nodeCap) revert NodeBoundExceeded();
            spentNode[rootId][nodeId][period] = ns + amount;
        }

        // Conservation: one shared slot for the entire tree. Under EVM
        // serialization this check-then-increment is atomic per transaction,
        // which is exactly what makes Σ(draws) <= cap an invariant.
        uint256 rs = spentRoot[rootId][period];
        if (rs + amount > root.cap) revert RootBoundExceeded();
        spentRoot[rootId][period] = rs + amount;

        emit Drawn(rootId, nodeId, period, amount);
    }

    // --------------------------------------------------------------------- //
    // Revocation                                                            //
    // --------------------------------------------------------------------- //

    /// @notice Revoke a node (and with it, transitively, every draw path through
    ///         its subtree). Authorized for the tree's issuer or the node's
    ///         parent agent. Revocation never refunds the root meter: realized
    ///         spend stays realized, so revocation can only shrink what the tree
    ///         can still draw, never mint headroom.
    function revoke(bytes32 rootId, uint64 nodeId) external {
        Root storage root = _rootOf(rootId);
        Node storage node = _nodeOf(rootId, nodeId);
        bool isIssuer = msg.sender == root.issuer;
        bool isParentAgent = nodeId != 0 && msg.sender == _nodes[rootId][node.parent].agent;
        if (!isIssuer && !isParentAgent) revert Unauthorized();
        node.revoked = true;
        emit NodeRevoked(rootId, nodeId);
    }

    // --------------------------------------------------------------------- //
    // Views — stranger-recomputable                                         //
    // --------------------------------------------------------------------- //

    function rootOf(bytes32 rootId)
        external
        view
        returns (address issuer, uint256 cap, uint64 periodLength, uint64 periodAnchor, uint64 nodeCount)
    {
        Root storage root = _rootOf(rootId);
        return (root.issuer, root.cap, root.periodLength, root.periodAnchor, root.nodeCount);
    }

    function nodeOf(bytes32 rootId, uint64 nodeId)
        external
        view
        returns (uint64 parent, uint8 depth, bool revoked, address agent, uint256 nodeCap)
    {
        Node storage node = _nodeOf(rootId, nodeId);
        return (node.parent, node.depth, node.revoked, node.agent, node.nodeCap);
    }

    /// @notice Remaining conserved headroom of the whole tree in the current period.
    function remainingRoot(bytes32 rootId) external view returns (uint256) {
        Root storage root = _rootOf(rootId);
        uint64 period = _periodIndex(root);
        uint256 rs = spentRoot[rootId][period];
        return rs >= root.cap ? 0 : root.cap - rs;
    }

    /// @notice Current period index of the tree (0 when periodLength == 0).
    function currentPeriod(bytes32 rootId) external view returns (uint64) {
        return _periodIndex(_rootOf(rootId));
    }

    /// @notice True iff every node from `nodeId` up to the root is unrevoked.
    function isPathActive(bytes32 rootId, uint64 nodeId) external view returns (bool) {
        _nodeOf(rootId, nodeId);
        uint64 cursor = nodeId;
        for (uint256 i = 0; i <= MAX_DEPTH; i++) {
            Node storage node = _nodes[rootId][cursor];
            if (node.revoked) return false;
            if (cursor == 0) return true;
            cursor = node.parent;
        }
        return false; // unreachable given MAX_DEPTH enforcement at delegate()
    }

    // --------------------------------------------------------------------- //
    // ERC-165                                                               //
    // --------------------------------------------------------------------- //

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IAggregateBudget).interfaceId;
    }

    // --------------------------------------------------------------------- //
    // Internal                                                              //
    // --------------------------------------------------------------------- //

    function _rootOf(bytes32 rootId) private view returns (Root storage root) {
        root = _roots[rootId];
        if (!root.exists) revert UnknownRoot();
    }

    function _nodeOf(bytes32 rootId, uint64 nodeId) private view returns (Node storage node) {
        node = _nodes[rootId][nodeId];
        if (!node.exists) revert UnknownNode();
    }

    function _requirePathActive(bytes32 rootId, uint64 nodeId) private view {
        uint64 cursor = nodeId;
        for (uint256 i = 0; i <= MAX_DEPTH; i++) {
            Node storage node = _nodes[rootId][cursor];
            if (node.revoked) revert PathRevoked();
            if (cursor == 0) return;
            cursor = node.parent;
        }
        // Unreachable given the depth cap enforced at delegate() (path length is
        // at most MAX_DEPTH+1). Fail CLOSED rather than open if that ever breaks.
        revert DepthExceeded();
    }

    function _periodIndex(Root storage root) private view returns (uint64) {
        if (root.periodLength == 0) return 0;
        if (block.timestamp < root.periodAnchor) revert PeriodNotStarted();
        return uint64((block.timestamp - root.periodAnchor) / root.periodLength);
    }
}
