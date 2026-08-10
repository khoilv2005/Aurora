// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract MerkleVerifyHarness {
    bytes32 private constant LEAF_TYPEHASH =
        keccak256("AuroraLeaf(address addr,uint256 amount,uint256 index)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public currentMerkleRoot;
    bool public lastVerifyResult;
    uint256[] public claimBitmap;

    constructor(bytes32 root, uint256 batchSize) {
        currentMerkleRoot = root;
        uint256 words = (batchSize + 255) / 256;
        for (uint256 i = 0; i < words; i++) {
            claimBitmap.push(0);
        }
    }

    function setRoot(bytes32 root) external {
        currentMerkleRoot = root;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("Aurora"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function _auroraLeafHash(address addr, uint256 amount, uint256 index) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(LEAF_TYPEHASH, addr, amount, index));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _verifyIndexed(bytes32 root, bytes32 leaf, bytes32[] calldata proof, uint256 index) internal pure returns (bool) {
        bytes32 computed = keccak256(abi.encodePacked(leaf));
        uint256 idx = index;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = idx % 2 == 0
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
            idx /= 2;
        }
        return computed == root;
    }

    function _verifyStandard(bytes32 root, bytes32 leaf, bytes32[] calldata proof) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = computed <= proof[i]
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
        }
        return computed == root;
    }

    function measureOZVerify(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external returns (bool) {
        bool ok = _verifyStandard(root, leaf, proof);
        lastVerifyResult = ok;
        return ok;
    }

    function measureAuroraVerify(address addr, uint256 amount, bytes32[] calldata proof, uint256 index) external returns (bool) {
        bool ok = _verifyIndexed(currentMerkleRoot, _auroraLeafHash(addr, amount, index), proof, index);
        lastVerifyResult = ok;
        return ok;
    }

    function claimAuroraBitmap(address addr, uint256 amount, bytes32[] calldata proof, uint256 index) external returns (bool) {
        bool ok = _verifyIndexed(currentMerkleRoot, _auroraLeafHash(addr, amount, index), proof, index);
        require(ok, "Invalid proof");

        uint256 wordIndex = index / 256;
        uint256 mask = uint256(1) << (index % 256);
        require((claimBitmap[wordIndex] & mask) == 0, "Already claimed");
        claimBitmap[wordIndex] |= mask;
        lastVerifyResult = true;
        return true;
    }
}
