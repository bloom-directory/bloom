// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract DeploymentBox {
    uint256 public value;
    constructor(uint256 initial) payable { value = initial; }
    function set(uint256 next) external { value = next; }
}
contract DeploymentRegistry {
    DeploymentBox public immutable box;
    constructor(DeploymentBox deployed) { box = deployed; }
}
