// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract BatchDAHarness {
    bytes32 public lastRoot;
    bytes32 public lastPayloadHash;
    uint256 public lastLeafCount;

    event LeafLogged(address indexed addr, uint256 amount, uint256 index);

    function submitCalldataRoot(bytes32 root, bytes calldata payload, uint256 leafCount) external {
        lastRoot = root;
        lastLeafCount = leafCount;
        lastPayloadHash = keccak256(payload);
    }

    function submitEventLeaves(bytes32 root, address[] calldata addrs, uint256[] calldata amounts) external {
        require(addrs.length == amounts.length, "Length mismatch");
        lastRoot = root;
        lastLeafCount = addrs.length;
        for (uint256 i = 0; i < addrs.length; i++) {
            emit LeafLogged(addrs[i], amounts[i], i);
        }
    }
}
