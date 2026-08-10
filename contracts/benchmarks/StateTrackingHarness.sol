// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract StateTrackingHarness {
    mapping(address => bool) public claimedByAddress;
    uint256[] public claimBitmap;

    event OperationMeasured(string method, uint256 opIndex, uint256 gasSpent);

    constructor(uint256 wordCount) {
        require(wordCount > 0, "wordCount=0");
        for (uint256 i = 0; i < wordCount; i++) {
            claimBitmap.push(0);
        }
    }

    function claimWithMapping(address user) external {
        require(!claimedByAddress[user], "Already claimed");
        claimedByAddress[user] = true;
    }

    function claimWithBitmap(uint256 index) external {
        uint256 wordIndex = index / 256;
        require(wordIndex < claimBitmap.length, "Index out of bounds");
        uint256 mask = uint256(1) << (index % 256);
        require((claimBitmap[wordIndex] & mask) == 0, "Already claimed");
        claimBitmap[wordIndex] |= mask;
    }

    function measureMappingOperation(address user, uint256 opIndex) external returns (uint256 gasSpent) {
        uint256 gasBefore = gasleft();
        require(!claimedByAddress[user], "Already claimed");
        claimedByAddress[user] = true;
        gasSpent = gasBefore - gasleft();
        emit OperationMeasured("mapping", opIndex, gasSpent);
    }

    function measureBitmapOperation(uint256 index) external returns (uint256 gasSpent) {
        uint256 gasBefore = gasleft();
        uint256 wordIndex = index / 256;
        require(wordIndex < claimBitmap.length, "Index out of bounds");
        uint256 mask = uint256(1) << (index % 256);
        require((claimBitmap[wordIndex] & mask) == 0, "Already claimed");
        claimBitmap[wordIndex] |= mask;
        gasSpent = gasBefore - gasleft();
        emit OperationMeasured("bitmap", index, gasSpent);
    }

    function bitmapWord(uint256 wordIndex) external view returns (uint256) {
        return claimBitmap[wordIndex];
    }
}
