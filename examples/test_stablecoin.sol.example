// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Example vulnerable stablecoin contract for testing ChainGuard
contract VulnerableStablecoin {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;
    
    // Missing: collateralization tracking
    // Missing: oracle price feeds
    // Missing: minimum collateral ratio
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerable: No access control on minting
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }
    
    // Missing: burn function for redemption
    // Missing: emergency pause mechanism
    // Missing: reentrancy protection
    // Missing: liquidation mechanism
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // Vulnerable: Single address can withdraw reserves
    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
} 