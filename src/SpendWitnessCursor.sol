// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IBoundedAgentAction} from "./IBoundedAgentAction.sol";
import {IBudgetSubstrate} from "./IBudgetSubstrate.sol";
import {IERC165} from "./IERC165.sol";
import {ISpendWitnessVerifier} from "./ISpendWitnessVerifier.sol";

/// @title SpendWitnessCursor
/// @notice Reference ERC-8312 budget cursor whose witness is a recomputable spend
///         authorization (e.g. BIP-340), validated by an external
///         ISpendWitnessVerifier. Conforms to the Budget Substrate Profile:
///         `capabilityRoot = keccak256(abi.encode(cap, asset))` and
///         `cursorRoot = keccak256(abi.encode(spent))`.
/// @dev    The cursor is witness-neutral: it never parses the witness. It pins an
///         issuer key per envelope, delegates verification to `verifier`, and meters
///         the verifier-returned amount against the bound with a per-envelope
///         draw-once nullifier. Advancement is bound to a validated witness, never to
///         an arbitrary caller, so an unauthorized party cannot advance a cursor
///         (the anti-griefing requirement). Like the minimal EnvelopeRegistry
///         reference it binds no assets and gates no execution path, so
///         non-bypassability and atomic bundling with the payment remain substrate
///         obligations, not properties of this contract.
contract SpendWitnessCursor is IBudgetSubstrate {
    struct Record {
        address principal;
        bytes32 capabilityRoot;
        bytes32 cursorRoot;
        uint64 createdAt;
        uint64 expiresAt;
        Status status; // stored status; reads fold in expiry
        uint256 cap;
        address asset;
        uint256 spent;
        bytes32 issuerKey; // x-only pubkey pinned at registration; the witness must verify against it
    }

    /// @notice The recomputable-witness verifier this cursor gates draws on.
    ISpendWitnessVerifier public immutable verifier;

    mapping(bytes32 => Record) private _records;
    /// @notice keccak256(abi.encode(id, nonce)) => drawn. Per-envelope draw-once.
    mapping(bytes32 => bool) public nullified;
    uint256 private _lock = 1;

    bytes32 private constant EMPTY_CURSOR = keccak256(abi.encode(uint256(0)));
    bytes32 private constant REGISTER_TYPEHASH = keccak256(
        "Register(address principal,bytes32 capabilityRoot,bytes32 issuerKey,uint64 expiresAt,bytes32 salt)"
    );

    error UnknownEnvelope();
    error IdExists();
    error BadExpiry();
    error CapabilityMismatch();
    error Unauthorized();
    error NotActive();
    error BoundExceeded();
    error BadWitness();
    error WitnessEnvelopeMismatch();
    error Replay();
    error BadTransition();
    error Reentrancy();
    error ZeroVerifier();

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(address verifier_) {
        if (verifier_ == address(0)) revert ZeroVerifier();
        verifier = ISpendWitnessVerifier(verifier_);
    }

    // --------------------------------------------------------------------- //
    // Registration                                                          //
    // --------------------------------------------------------------------- //

    /// @notice Deterministic id derivation; the issuer key is part of the id so two
    ///         otherwise-identical mandates with different delegated keys never collide.
    function computeId(address principal, bytes32 capabilityRoot, bytes32 issuerKey_, bytes32 salt)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), principal, capabilityRoot, issuerKey_, salt));
    }

    /// @inheritdoc IBoundedAgentAction
    /// @dev initData = abi.encode(uint256 cap, address asset, bytes32 issuerKey, bytes32 salt, bytes principalSig).
    ///      capabilityRoot MUST equal keccak256(abi.encode(cap, asset)). If principal
    ///      != msg.sender, principalSig MUST be a valid EIP-712 signature by principal
    ///      over the registration digest, which binds the issuer key it is delegating to.
    function registerEnvelope(address principal, bytes32 capabilityRoot, uint64 expiresAt, bytes calldata initData)
        external
        returns (bytes32 id)
    {
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert BadExpiry();

        (uint256 cap, address asset, bytes32 issuerKey_, bytes32 salt, bytes memory principalSig) =
            abi.decode(initData, (uint256, address, bytes32, bytes32, bytes));
        if (capabilityRoot != keccak256(abi.encode(cap, asset))) revert CapabilityMismatch();

        id = computeId(principal, capabilityRoot, issuerKey_, salt);
        if (_records[id].status != Status.None) revert IdExists();

        if (principal != msg.sender) {
            bytes32 d = registrationDigest(principal, capabilityRoot, issuerKey_, expiresAt, salt);
            if (_recover(d, principalSig) != principal) revert Unauthorized();
        }

        Record storage r = _records[id];
        r.principal = principal;
        r.capabilityRoot = capabilityRoot;
        r.cursorRoot = EMPTY_CURSOR;
        r.createdAt = uint64(block.timestamp);
        r.expiresAt = expiresAt;
        r.status = Status.Active;
        r.cap = cap;
        r.asset = asset;
        r.issuerKey = issuerKey_;

        emit EnvelopeRegistered(id, principal, capabilityRoot);
    }

    // --------------------------------------------------------------------- //
    // Reads (all revert on unknown id; status folds in expiry)              //
    // --------------------------------------------------------------------- //

    function getEnvelope(bytes32 id) external view returns (Envelope memory) {
        Record storage r = _get(id);
        return Envelope({
            id: id,
            principal: r.principal,
            capabilityRoot: r.capabilityRoot,
            cursorRoot: r.cursorRoot,
            createdAt: r.createdAt,
            expiresAt: r.expiresAt,
            status: _effective(r)
        });
    }

    function getCursor(bytes32 id) external view returns (bytes32) {
        return _get(id).cursorRoot;
    }

    function getStatus(bytes32 id) external view returns (Status) {
        return _effective(_get(id));
    }

    function isActive(bytes32 id) external view returns (bool) {
        return _effective(_get(id)) == Status.Active;
    }

    /// @notice The x-only issuer key a draw witness must verify against for this envelope.
    function issuerKeyOf(bytes32 id) external view returns (bytes32) {
        return _get(id).issuerKey;
    }

    function bound(bytes32 id) external view returns (uint256 cap, address asset) {
        Record storage r = _get(id);
        return (r.cap, r.asset);
    }

    function spent(bytes32 id) external view returns (uint256) {
        return _get(id).spent;
    }

    function remaining(bytes32 id) external view returns (uint256) {
        Record storage r = _get(id);
        if (_effective(r) != Status.Active) return 0;
        return r.cap - r.spent;
    }

    // --------------------------------------------------------------------- //
    // Advance                                                               //
    // --------------------------------------------------------------------- //

    /// @inheritdoc IBoundedAgentAction
    /// @dev `witness` is opaque to the cursor. It is handed to `verifier`, which
    ///      returns the recomputed verdict plus the (amount, cursorId, nonce) read out
    ///      of the same signed preimage. The draw is admitted only if the verdict is
    ///      valid, the witness was signed for THIS envelope, it stays within the bound,
    ///      and its nonce has not been drawn before.
    function advanceCursor(bytes32 id, bytes calldata witness) external nonReentrant returns (bytes32 newCursor) {
        Record storage r = _get(id);
        if (_effective(r) != Status.Active) revert NotActive();

        (bool valid, uint256 amount, bytes32 cursorId, bytes32 nonce) = verifier.verifySpend(r.issuerKey, witness);
        if (!valid) revert BadWitness();
        if (cursorId != id) revert WitnessEnvelopeMismatch();
        if (r.spent + amount > r.cap) revert BoundExceeded();

        bytes32 nk = keccak256(abi.encode(id, nonce));
        if (nullified[nk]) revert Replay();

        // checks-effects: state finalized before returning; no external state-changing calls.
        nullified[nk] = true;
        r.spent += amount;
        bytes32 prevCursor = r.cursorRoot;
        newCursor = keccak256(abi.encode(r.spent));
        r.cursorRoot = newCursor;
        emit EnvelopeAdvanced(id, prevCursor, newCursor);
    }

    // --------------------------------------------------------------------- //
    // Lifecycle (base transitions only; Contested is not supported here)    //
    // --------------------------------------------------------------------- //

    function setStatus(bytes32 id, Status newStatus) external {
        Record storage r = _get(id);
        Status cur = r.status;
        if (cur != Status.Active) revert BadTransition();

        bool expired = r.expiresAt != 0 && block.timestamp >= r.expiresAt;
        if (newStatus == Status.Expired) {
            if (!expired) revert BadTransition();
            // permissionless once the expiry timestamp is reached
        } else {
            if (expired) revert BadTransition(); // effectively expired: the only exit is Expired
            if (newStatus == Status.Revoked || newStatus == Status.Completed) {
                if (msg.sender != r.principal) revert Unauthorized();
            } else {
                revert BadTransition(); // Contested / Active / None not permitted by the base registry
            }
        }

        r.status = newStatus;
        emit EnvelopeStatusChanged(id, cur, newStatus);
    }

    // --------------------------------------------------------------------- //
    // ERC-165                                                               //
    // --------------------------------------------------------------------- //

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IBoundedAgentAction).interfaceId
            || interfaceId == type(IBudgetSubstrate).interfaceId;
    }

    // --------------------------------------------------------------------- //
    // EIP-712 digest helpers (registration only; draw auth lives in verify) //
    // --------------------------------------------------------------------- //

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("BoundedAgentActions"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function registrationDigest(
        address principal,
        bytes32 capabilityRoot,
        bytes32 issuerKey_,
        uint64 expiresAt,
        bytes32 salt
    ) public view returns (bytes32) {
        return _digest(keccak256(abi.encode(REGISTER_TYPEHASH, principal, capabilityRoot, issuerKey_, expiresAt, salt)));
    }

    // --------------------------------------------------------------------- //
    // Internal                                                              //
    // --------------------------------------------------------------------- //

    function _get(bytes32 id) private view returns (Record storage r) {
        r = _records[id];
        if (r.status == Status.None) revert UnknownEnvelope();
    }

    function _effective(Record storage r) private view returns (Status) {
        if (r.status == Status.Active && r.expiresAt != 0 && block.timestamp >= r.expiresAt) {
            return Status.Expired;
        }
        return r.status;
    }

    function _digest(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _recover(bytes32 digest, bytes memory sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(digest, v, r, s);
    }
}
