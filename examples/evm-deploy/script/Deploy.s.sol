// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {DeploymentBox, DeploymentRegistry} from "../contracts/DeploymentExample.sol";
interface Vm { function startBroadcast() external; function stopBroadcast() external; }
contract Deploy {
    function run() external {
        Vm vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
        vm.startBroadcast();
        DeploymentBox box = new DeploymentBox{value: 123}(7);
        new DeploymentRegistry(box);
        box.set(9);
        vm.stopBroadcast();
    }
}
