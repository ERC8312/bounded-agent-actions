// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendWitnessCursor} from "../src/SpendWitnessCursor.sol";
import {ISpendWitnessVerifier} from "../src/ISpendWitnessVerifier.sol";
import {IBoundedAgentAction} from "../src/IBoundedAgentAction.sol";
import {IBudgetSubstrate} from "../src/IBudgetSubstrate.sol";
import {IERC165} from "../src/IERC165.sol";

/// @notice Controllable verifier for testing. The witness IS the verdict:
///         abi.encode(expectedIssuer, sigValid, amount, cursorId, nonce). It returns
///         valid only when the cursor passes the issuer key the witness was signed by,
///         mirroring a real verifier whose `valid` requires the signature be by `issuerKey`.
contract MockSpendWitnessVerifier is ISpendWitnessVerifier {
    function verifySpend(bytes32 issuerKey, bytes calldata witness)
        external
        pure
        returns (bool valid, uint256 amount, bytes32 cursorId, bytes32 nonce)
    {
        bytes32 expectedIssuer;
        bool sigValid;
        (expectedIssuer, sigValid, amount, cursorId, nonce) =
            abi.decode(witness, (bytes32, bool, uint256, bytes32, bytes32));
        valid = sigValid && (issuerKey == expectedIssuer);
    }
}

contract SpendWitnessCursorTest is Test {
    SpendWitnessCursor internal cursor;
    MockSpendWitnessVerifier internal mock;

    bytes32 internal constant ISSUER = bytes32(uint256(0xA11CE));
    address internal constant ASSET = address(0);
    uint256 internal constant CAP = 1 ether;
    bytes32 internal constant EMPTY_CURSOR = keccak256(abi.encode(uint256(0)));

    event EnvelopeRegistered(bytes32 indexed id, address indexed principal, bytes32 indexed capabilityRoot);
    event EnvelopeAdvanced(bytes32 indexed id, bytes32 prevCursor, bytes32 newCursor);
    event EnvelopeStatusChanged(
        bytes32 indexed id, IBoundedAgentAction.Status fromStatus, IBoundedAgentAction.Status toStatus
    );

    function setUp() public {
        mock = new MockSpendWitnessVerifier();
        cursor = new SpendWitnessCursor(address(mock));
    }

    // ----------------------------- helpers ------------------------------- //

    function _capRoot(uint256 cap, address asset) internal pure returns (bytes32) {
        return keccak256(abi.encode(cap, asset));
    }

    function _register(uint256 cap, address asset, bytes32 issuer, bytes32 salt) internal returns (bytes32 id) {
        bytes memory initData = abi.encode(cap, asset, issuer, salt, bytes(""));
        id = cursor.registerEnvelope(address(this), _capRoot(cap, asset), 0, initData);
    }

    function _registerDefault() internal returns (bytes32 id) {
        id = _register(CAP, ASSET, ISSUER, bytes32(uint256(1)));
    }

    function _witness(bytes32 issuer, bool sigValid, uint256 amount, bytes32 cursorId, bytes32 nonce)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(issuer, sigValid, amount, cursorId, nonce);
    }

    // --------------------------- constructor ----------------------------- //

    function test_constructor_revertsZeroVerifier() public {
        vm.expectRevert(SpendWitnessCursor.ZeroVerifier.selector);
        new SpendWitnessCursor(address(0));
    }

    function test_constructor_setsVerifier() public view {
        assertEq(address(cursor.verifier()), address(mock));
    }

    // --------------------------- registration ---------------------------- //

    function test_register_storesFields() public {
        bytes32 id = _registerDefault();
        IBoundedAgentAction.Envelope memory e = cursor.getEnvelope(id);
        assertEq(e.principal, address(this));
        assertEq(e.capabilityRoot, _capRoot(CAP, ASSET));
        assertEq(e.cursorRoot, EMPTY_CURSOR);
        assertEq(uint8(e.status), uint8(IBoundedAgentAction.Status.Active));
        (uint256 cap, address asset) = cursor.bound(id);
        assertEq(cap, CAP);
        assertEq(asset, ASSET);
        assertEq(cursor.issuerKeyOf(id), ISSUER);
        assertEq(cursor.spent(id), 0);
        assertEq(cursor.remaining(id), CAP);
        assertEq(cursor.getCursor(id), EMPTY_CURSOR);
        assertTrue(cursor.isActive(id));
    }

    function test_register_emitsEvent() public {
        bytes32 capRoot = _capRoot(CAP, ASSET);
        bytes32 expectedId = cursor.computeId(address(this), capRoot, ISSUER, bytes32(uint256(1)));
        vm.expectEmit(true, true, true, true);
        emit EnvelopeRegistered(expectedId, address(this), capRoot);
        _registerDefault();
    }

    function test_register_revertsCapabilityMismatch() public {
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, bytes32(uint256(1)), bytes(""));
        vm.expectRevert(SpendWitnessCursor.CapabilityMismatch.selector);
        cursor.registerEnvelope(address(this), keccak256("wrong"), 0, initData);
    }

    function test_register_revertsIdExists() public {
        _registerDefault();
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, bytes32(uint256(1)), bytes(""));
        vm.expectRevert(SpendWitnessCursor.IdExists.selector);
        cursor.registerEnvelope(address(this), _capRoot(CAP, ASSET), 0, initData);
    }

    function test_register_revertsBadExpiry() public {
        vm.warp(1000);
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, bytes32(uint256(1)), bytes(""));
        vm.expectRevert(SpendWitnessCursor.BadExpiry.selector);
        cursor.registerEnvelope(address(this), _capRoot(CAP, ASSET), uint64(500), initData);
    }

    function test_register_thirdParty_validSig() public {
        uint256 pk = 0xA11CE;
        address principal = vm.addr(pk);
        bytes32 capRoot = _capRoot(CAP, ASSET);
        bytes32 salt = bytes32(uint256(7));
        bytes32 digest = cursor.registrationDigest(principal, capRoot, ISSUER, 0, salt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, salt, sig);
        bytes32 id = cursor.registerEnvelope(principal, capRoot, 0, initData);
        assertEq(cursor.getEnvelope(id).principal, principal);
    }

    function test_register_thirdParty_revertsBadSig() public {
        uint256 pk = 0xA11CE;
        uint256 wrongPk = 0xB0B;
        address principal = vm.addr(pk);
        bytes32 capRoot = _capRoot(CAP, ASSET);
        bytes32 salt = bytes32(uint256(7));
        bytes32 digest = cursor.registrationDigest(principal, capRoot, ISSUER, 0, salt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, salt, sig);
        vm.expectRevert(SpendWitnessCursor.Unauthorized.selector);
        cursor.registerEnvelope(principal, capRoot, 0, initData);
    }

    // ------------------------------ advance ------------------------------ //

    function test_advance_validDraw() public {
        bytes32 id = _registerDefault();
        uint256 amount = 0.3 ether;
        bytes32 nonce = bytes32(uint256(0x1234));
        bytes memory w = _witness(ISSUER, true, amount, id, nonce);
        bytes32 expectedCursor = keccak256(abi.encode(amount));

        vm.expectEmit(true, false, false, true);
        emit EnvelopeAdvanced(id, EMPTY_CURSOR, expectedCursor);
        bytes32 nc = cursor.advanceCursor(id, w);

        assertEq(nc, expectedCursor);
        assertEq(cursor.spent(id), amount);
        assertEq(cursor.remaining(id), CAP - amount);
        assertEq(cursor.getCursor(id), expectedCursor);
        assertTrue(cursor.nullified(keccak256(abi.encode(id, nonce))));
    }

    function test_advance_revertsBadWitness() public {
        bytes32 id = _registerDefault();
        bytes memory w = _witness(ISSUER, false, 0.1 ether, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.BadWitness.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_revertsWrongIssuer() public {
        bytes32 id = _registerDefault();
        // signed by a key other than the one pinned at registration
        bytes memory w = _witness(bytes32(uint256(0xDEAD)), true, 0.1 ether, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.BadWitness.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_revertsEnvelopeMismatch() public {
        bytes32 id = _registerDefault();
        bytes32 otherId = bytes32(uint256(0x9999));
        bytes memory w = _witness(ISSUER, true, 0.1 ether, otherId, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.WitnessEnvelopeMismatch.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_revertsOverBound() public {
        bytes32 id = _registerDefault();
        bytes memory w = _witness(ISSUER, true, CAP + 1, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.BoundExceeded.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_exactBound() public {
        bytes32 id = _registerDefault();
        bytes memory w = _witness(ISSUER, true, CAP, id, bytes32(uint256(1)));
        cursor.advanceCursor(id, w);
        assertEq(cursor.spent(id), CAP);
        assertEq(cursor.remaining(id), 0);
    }

    function test_advance_revertsReplay() public {
        bytes32 id = _registerDefault();
        bytes32 nonce = bytes32(uint256(0x5));
        bytes memory w = _witness(ISSUER, true, 0.1 ether, id, nonce);
        cursor.advanceCursor(id, w);
        vm.expectRevert(SpendWitnessCursor.Replay.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_differentNonceAccumulates() public {
        bytes32 id = _registerDefault();
        cursor.advanceCursor(id, _witness(ISSUER, true, 0.2 ether, id, bytes32(uint256(1))));
        cursor.advanceCursor(id, _witness(ISSUER, true, 0.3 ether, id, bytes32(uint256(2))));
        assertEq(cursor.spent(id), 0.5 ether);
        assertEq(cursor.remaining(id), CAP - 0.5 ether);
    }

    function test_advance_revertsUnknownId() public {
        bytes32 id = bytes32(uint256(0xBEEF));
        bytes memory w = _witness(ISSUER, true, 0.1 ether, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.UnknownEnvelope.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_revertsWhenRevoked() public {
        bytes32 id = _registerDefault();
        cursor.setStatus(id, IBoundedAgentAction.Status.Revoked);
        bytes memory w = _witness(ISSUER, true, 0.1 ether, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.NotActive.selector);
        cursor.advanceCursor(id, w);
    }

    function test_advance_revertsWhenExpired() public {
        vm.warp(1000);
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, bytes32(uint256(1)), bytes(""));
        bytes32 id = cursor.registerEnvelope(address(this), _capRoot(CAP, ASSET), uint64(2000), initData);
        vm.warp(2001);
        bytes memory w = _witness(ISSUER, true, 0.1 ether, id, bytes32(uint256(1)));
        vm.expectRevert(SpendWitnessCursor.NotActive.selector);
        cursor.advanceCursor(id, w);
    }

    // ----------------------------- lifecycle ----------------------------- //

    function test_setStatus_revoke() public {
        bytes32 id = _registerDefault();
        vm.expectEmit(true, false, false, true);
        emit EnvelopeStatusChanged(id, IBoundedAgentAction.Status.Active, IBoundedAgentAction.Status.Revoked);
        cursor.setStatus(id, IBoundedAgentAction.Status.Revoked);
        assertEq(uint8(cursor.getStatus(id)), uint8(IBoundedAgentAction.Status.Revoked));
    }

    function test_setStatus_completed() public {
        bytes32 id = _registerDefault();
        cursor.setStatus(id, IBoundedAgentAction.Status.Completed);
        assertEq(uint8(cursor.getStatus(id)), uint8(IBoundedAgentAction.Status.Completed));
    }

    function test_setStatus_revertsNonPrincipal() public {
        bytes32 id = _registerDefault();
        vm.prank(address(0xBEEF));
        vm.expectRevert(SpendWitnessCursor.Unauthorized.selector);
        cursor.setStatus(id, IBoundedAgentAction.Status.Revoked);
    }

    function test_setStatus_revertsContested() public {
        bytes32 id = _registerDefault();
        vm.expectRevert(SpendWitnessCursor.BadTransition.selector);
        cursor.setStatus(id, IBoundedAgentAction.Status.Contested);
    }

    function test_setStatus_expirePermissionless() public {
        vm.warp(1000);
        bytes memory initData = abi.encode(CAP, ASSET, ISSUER, bytes32(uint256(1)), bytes(""));
        bytes32 id = cursor.registerEnvelope(address(this), _capRoot(CAP, ASSET), uint64(2000), initData);
        vm.warp(2001);
        vm.prank(address(0xBEEF)); // anyone can expire once the timestamp passes
        cursor.setStatus(id, IBoundedAgentAction.Status.Expired);
        assertEq(uint8(cursor.getStatus(id)), uint8(IBoundedAgentAction.Status.Expired));
    }

    function test_remaining_zeroWhenInactive() public {
        bytes32 id = _registerDefault();
        cursor.setStatus(id, IBoundedAgentAction.Status.Revoked);
        assertEq(cursor.remaining(id), 0);
    }

    // ---------------------------- conformance ---------------------------- //

    function test_supportsInterface() public view {
        assertTrue(cursor.supportsInterface(type(IERC165).interfaceId));
        assertTrue(cursor.supportsInterface(type(IBoundedAgentAction).interfaceId));
        assertTrue(cursor.supportsInterface(type(IBudgetSubstrate).interfaceId));
        assertFalse(cursor.supportsInterface(0xffffffff));
        assertFalse(cursor.supportsInterface(0xe664d441)); // IContestableEnvelope not supported
    }

    function test_getCursor_equalsSpentCommitment() public {
        bytes32 id = _registerDefault();
        cursor.advanceCursor(id, _witness(ISSUER, true, 0.4 ether, id, bytes32(uint256(1))));
        assertEq(cursor.getCursor(id), keccak256(abi.encode(uint256(0.4 ether))));
    }

    function test_reads_revertUnknownId() public {
        bytes32 id = bytes32(uint256(0xC0FFEE));
        vm.expectRevert(SpendWitnessCursor.UnknownEnvelope.selector);
        cursor.getCursor(id);
        vm.expectRevert(SpendWitnessCursor.UnknownEnvelope.selector);
        cursor.bound(id);
        vm.expectRevert(SpendWitnessCursor.UnknownEnvelope.selector);
        cursor.remaining(id);
    }

    // ------------------------------- fuzz -------------------------------- //

    function testFuzz_drawNeverExceedsCap(uint256 amount) public {
        bytes32 id = _registerDefault();
        bytes memory w = _witness(ISSUER, true, amount, id, bytes32(uint256(1)));
        if (amount > CAP) {
            vm.expectRevert(SpendWitnessCursor.BoundExceeded.selector);
            cursor.advanceCursor(id, w);
            assertEq(cursor.spent(id), 0);
        } else {
            cursor.advanceCursor(id, w);
            assertEq(cursor.spent(id), amount);
            assertLe(cursor.spent(id), CAP);
        }
    }

    function testFuzz_multiDrawNeverExceedsCap(uint256 a1, uint256 a2, uint256 a3) public {
        a1 = a1 % (CAP + 1);
        a2 = a2 % (CAP + 1);
        a3 = a3 % (CAP + 1);
        bytes32 id = _registerDefault();
        _tryDraw(id, a1, bytes32(uint256(1)));
        _tryDraw(id, a2, bytes32(uint256(2)));
        _tryDraw(id, a3, bytes32(uint256(3)));
        assertLe(cursor.spent(id), CAP);
    }

    function _tryDraw(bytes32 id, uint256 amount, bytes32 nonce) internal {
        bytes memory w = _witness(ISSUER, true, amount, id, nonce);
        try cursor.advanceCursor(id, w) {} catch {}
    }
}

/// @notice Drives random draws against one envelope for the invariant suite. Each
///         call uses a fresh nonce (so it is never a replay) and a valid witness, so
///         the only thing that can stop a draw is the bound itself.
contract SpendWitnessHandler {
    SpendWitnessCursor internal immutable CURSOR;
    bytes32 internal immutable ID;
    bytes32 internal constant ISSUER = bytes32(uint256(0xA11CE));
    uint256 internal constant CAP = 1 ether;
    uint256 public draws;

    constructor(SpendWitnessCursor cursor_, bytes32 id_) {
        CURSOR = cursor_;
        ID = id_;
    }

    function draw(uint256 amount, uint256 nonceSeed) external {
        // keep amounts in a band where draws sometimes succeed and sometimes exceed
        amount = amount % (CAP + (CAP / 2) + 1);
        bytes32 nonce = keccak256(abi.encode(nonceSeed, draws));
        bytes memory w = abi.encode(ISSUER, true, amount, ID, nonce);
        try CURSOR.advanceCursor(ID, w) {
            draws++;
        } catch {}
    }
}

/// @notice Stateful invariants: no sequence of draws can breach the bound or the
///         Budget Substrate Profile commitment, and remaining stays exact.
contract SpendWitnessCursorInvariants is Test {
    SpendWitnessCursor internal cursor;
    MockSpendWitnessVerifier internal mock;
    SpendWitnessHandler internal handler;
    bytes32 internal id;

    uint256 internal constant CAP = 1 ether;
    bytes32 internal constant ISSUER = bytes32(uint256(0xA11CE));

    function setUp() public {
        mock = new MockSpendWitnessVerifier();
        cursor = new SpendWitnessCursor(address(mock));
        bytes32 capRoot = keccak256(abi.encode(CAP, address(0)));
        bytes memory initData = abi.encode(CAP, address(0), ISSUER, bytes32(uint256(1)), bytes(""));
        id = cursor.registerEnvelope(address(this), capRoot, 0, initData);
        handler = new SpendWitnessHandler(cursor, id);
        targetContract(address(handler));
    }

    /// @dev The metering guarantee: cumulative draws never exceed the bound.
    function invariant_spentNeverExceedsCap() public view {
        assertLe(cursor.spent(id), CAP);
    }

    /// @dev The Budget Substrate Profile MUST: cursorRoot == keccak256(abi.encode(spent)).
    function invariant_cursorRootCommitsSpent() public view {
        assertEq(cursor.getCursor(id), keccak256(abi.encode(cursor.spent(id))));
    }

    /// @dev remaining() stays exactly cap - spent while the envelope is active.
    function invariant_remainingIsExact() public view {
        assertEq(cursor.remaining(id), CAP - cursor.spent(id));
    }
}
