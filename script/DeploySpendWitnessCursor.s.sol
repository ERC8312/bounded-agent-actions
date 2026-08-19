// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SpendWitnessCursor} from "../src/SpendWitnessCursor.sol";

/// @title DeploySpendWitnessCursor
/// @notice Deploys a SpendWitnessCursor pointing at an already-deployed
///         ISpendWitnessVerifier (babyblueviper1's spend-witness verify on the
///         target chain). Target chain for the wiring test is Gnosis Chiado (10200).
///
/// @dev Minimal deploy:
///   export VERIFIER_ADDRESS=0x...                 # babyblueviper1's Chiado verifier
///   forge script script/DeploySpendWitnessCursor.s.sol:DeploySpendWitnessCursor \
///     --rpc-url https://rpc.chiadochain.net \
///     --private-key "$DEPLOYER_PK" --broadcast
///
/// Optionally register one demo envelope in the same run (principal = deployer, so no
/// signature needed). For the real integration GhostAgent's Safe registers instead.
///   export REGISTER=true
///   export ISSUER_KEY=0x...                       # GhostAgent's x-only BIP-340 pubkey
///   export CAP=1000000000000000000                # 1e18 wei
///   export ASSET=0x0000000000000000000000000000000000000000
contract DeploySpendWitnessCursor is Script {
    function run() external returns (SpendWitnessCursor cursor) {
        address verifier = vm.envAddress("VERIFIER_ADDRESS");
        require(verifier != address(0), "VERIFIER_ADDRESS not set");

        vm.startBroadcast();

        cursor = new SpendWitnessCursor(verifier);
        console.log("SpendWitnessCursor:", address(cursor));
        console.log("  verifier        :", address(cursor.verifier()));
        console.log("  chainid         :", block.chainid);

        if (vm.envOr("REGISTER", false)) {
            bytes32 issuerKey = vm.envBytes32("ISSUER_KEY");
            uint256 cap = vm.envUint("CAP");
            address asset = vm.envAddress("ASSET");
            bytes32 salt = bytes32(uint256(1));
            bytes32 capRoot = keccak256(abi.encode(cap, asset));
            // principal == broadcaster, so the EIP-712 principal signature is skipped
            bytes memory initData = abi.encode(cap, asset, issuerKey, salt, bytes(""));
            bytes32 id = cursor.registerEnvelope(msg.sender, capRoot, 0, initData);
            console.log("  registered envelope id:");
            console.logBytes32(id);
            console.log("  cap             :", cap);
            console.log("  issuerKey       :");
            console.logBytes32(issuerKey);
        }

        vm.stopBroadcast();
    }
}
