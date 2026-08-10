// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract AuroraNoDuHarness {
    bytes32 private constant LEAF_TYPEHASH =
        keccak256("AuroraLeaf(address addr,uint256 amount,uint256 index)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    event StateSeeded(uint256 claimedCount, bool proofSubmitted, bool disputeOpened, bool disputeClosedP, bool disputeClosedV);
    event UserRegistered(address indexed user);
    event BatchSubmitted(bytes32 indexed merkleRoot, uint256 indexed batchSize);
    event LeafClaimed(bytes32 indexed merkleRoot, uint256 indexed index);
    event DisputeFrozen(uint256 frozenAmount, uint256 frozenAt);

    address public immutable prover;
    address public immutable verifier;

    mapping(address => uint256) public initBalEth;
    mapping(address => bool) public registeredUsers;

    uint256 public totalSupply;
    bytes32 public currentMerkleRoot;
    uint256 public batchSize;
    uint256[] public claimBitmap;
    uint256 public claimedCount;

    bool public proofSubmitted;
    bool public disputeOpened;
    bool public disputeClosedP;
    bool public disputeClosedV;
    bool public settled;
    bool public frozen;
    uint256 public frozenAt;
    uint256 public frozenAmount;

    constructor(address _prover, address _verifier) {
        prover = _prover;
        verifier = _verifier;
    }

    receive() external payable {
        initBalEth[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function registerIntent() external {
        require(currentMerkleRoot == bytes32(0), "Root already submitted");
        require(!registeredUsers[msg.sender], "Already registered");
        registeredUsers[msg.sender] = true;
        emit UserRegistered(msg.sender);
    }

    function seedRegistered(address user) external {
        registeredUsers[user] = true;
    }

    function seedSettlementState(
        uint256 _claimedCount,
        bool _proofSubmitted,
        bool _disputeOpened,
        bool _disputeClosedP,
        bool _disputeClosedV
    ) external {
        claimedCount = _claimedCount;
        proofSubmitted = _proofSubmitted;
        disputeOpened = _disputeOpened;
        disputeClosedP = _disputeClosedP;
        disputeClosedV = _disputeClosedV;
        emit StateSeeded(_claimedCount, _proofSubmitted, _disputeOpened, _disputeClosedP, _disputeClosedV);
    }

    function submitMerkleRoot(bytes32 merkleRoot, uint256 _batchSize) external {
        require(msg.sender == prover, "Only prover");
        require(_batchSize > 0 && (_batchSize & (_batchSize - 1)) == 0, "Batch size must be a power of two");
        require(currentMerkleRoot == bytes32(0), "Batch already submitted");

        currentMerkleRoot = merkleRoot;
        batchSize = _batchSize;

        uint256 numWords = (_batchSize + 255) / 256;
        for (uint256 i = 0; i < numWords; i++) {
            claimBitmap.push(0);
        }

        emit BatchSubmitted(merkleRoot, _batchSize);
    }

    function claimWithMerkleProof(
        address addr,
        uint256 amount,
        bytes32[] calldata merkleProof,
        uint256 index
    ) external {
        require(currentMerkleRoot != bytes32(0), "No batch submitted");
        require(index < batchSize, "Index out of bounds");
        require(verifyMerkleProof(currentMerkleRoot, _leafHash(addr, amount, index), merkleProof, index), "Invalid Merkle proof");
        require(!isClaimed(index), "Already claimed");
        require(msg.sender == addr, "Must claim own leaf");
        require(registeredUsers[addr], "Addr not pre-registered");

        _setClaimed(index);
        claimedCount++;
        emit LeafClaimed(currentMerkleRoot, index);
    }

    function settle() external {
        require(!settled, "Already settled");
        settled = true;

        if (proofSubmitted || (disputeOpened && disputeClosedP)) {
            uint256 proverShare = (totalSupply * 7) / 100;
            uint256 verifierShare = totalSupply - proverShare;
            if (proverShare > 0) {
                (bool okP,) = prover.call{value: proverShare}("");
                require(okP, "Prover transfer failed");
            }
            if (verifierShare > 0) {
                (bool okV,) = verifier.call{value: verifierShare}("");
                require(okV, "Verifier transfer failed");
            }
        } else if (currentMerkleRoot != bytes32(0) && claimedCount > 0) {
            uint256 proverShare = (totalSupply * claimedCount) / batchSize;
            uint256 verifierShare = totalSupply - proverShare;
            if (proverShare > 0) {
                (bool okP,) = prover.call{value: proverShare}("");
                require(okP, "Prover transfer failed");
            }
            if (verifierShare > 0) {
                (bool okV,) = verifier.call{value: verifierShare}("");
                require(okV, "Verifier transfer failed");
            }
        } else if (currentMerkleRoot != bytes32(0) && claimedCount == 0 && !disputeOpened) {
            (bool okP,) = prover.call{value: initBalEth[prover]}("");
            require(okP, "Prover refund failed");
            (bool okV,) = verifier.call{value: initBalEth[verifier]}("");
            require(okV, "Verifier refund failed");
        } else if (disputeOpened && !disputeClosedP && !disputeClosedV) {
            frozenAmount = totalSupply;
            frozen = true;
            frozenAt = block.timestamp;
            emit DisputeFrozen(frozenAmount, frozenAt);
        } else if (disputeOpened && disputeClosedV) {
            (bool okV,) = verifier.call{value: totalSupply}("");
            require(okV, "Verifier transfer failed");
        } else {
            settled = false;
            revert("No valid settlement condition met");
        }
    }

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 wordIndex = index / 256;
        uint256 bitIndex = index % 256;
        if (wordIndex >= claimBitmap.length) return false;
        return (claimBitmap[wordIndex] & (uint256(1) << bitIndex)) != 0;
    }

    function getBitmapWord(uint256 wordIndex) external view returns (uint256) {
        if (wordIndex >= claimBitmap.length) return 0;
        return claimBitmap[wordIndex];
    }

    function _setClaimed(uint256 index) internal {
        claimBitmap[index / 256] |= (uint256(1) << (index % 256));
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

    function _leafHash(address addr, uint256 amount, uint256 index) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(LEAF_TYPEHASH, addr, amount, index));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function verifyMerkleProof(bytes32 root, bytes32 leaf, bytes32[] calldata proof, uint256 index) internal pure returns (bool) {
        bytes32 computedHash = keccak256(bytes.concat(leaf));
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            computedHash = index % 2 == 0
                ? keccak256(abi.encodePacked(computedHash, proofElement))
                : keccak256(abi.encodePacked(proofElement, computedHash));
            index /= 2;
        }
        return computedHash == root;
    }
}
