// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./ParseBTCLib.sol";
import "./BytesLib.sol";
import "./ECDSA.sol";
import "./AuroraHelperExt.sol";

/**
 * @title AuroraFullTestnet
 * @dev Full Aurora contract - logic identical to AuroraFull.
 *      Deployed on Sepolia testnet for end-to-end validation.
 *
 * Settlement paths:
 *   Path 1  - submitProof (BTC) OR resolveValidDispute -> balDistr split
 *   Path 2  - batch proportional (claimedCount > 0)
 *   Path 2b - batch zero-claim timeout -> deposit refund
 *   Path 3  - dispute unresolved -> D frozen for arbitration
 *   Path 4  - resolveInvalidDispute (revocation) -> all to verifier
 *   Path 5  - no setup -> deposit refund
 */
contract AuroraFullTestnet {

    // -- EIP-712: Typed Structured Data Hashing -------------------------------
    bytes32 private constant LEAF_TYPEHASH =
        keccak256("AuroraLeaf(address addr,uint256 amount,uint256 index,bytes32 obligationCommitment)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    event stateEvent(string label, bool status);
    event lockEvent(string label, address addr, uint amount);
    event batchProofSubmitted(bytes32 indexed merkleRoot, uint256 leafCount);
    event leafClaimed(bytes32 indexed merkleRoot, uint256 indexed index);
    event batchBlobCommitted(bytes32 indexed merkleRoot, bytes32 indexed blobCommitment, uint256 leafCount);
    event leafChallenged(bytes32 indexed merkleRoot, uint256 indexed index, address challenger);
    event challengeRejected(bytes32 indexed merkleRoot, uint256 indexed index, string reason);
    event userPoolDeposited(uint256 amount);
    event userPoolBurned(uint256 amount);
    event userPaid(uint256 indexed index, address addr, uint256 amount);
    event UserRegistered(address indexed user, uint256 indexed index, uint256 amount, bytes32 obligationCommitment);

    struct AuroraParam {
        bytes32 fundTxId;
        bytes fundTxScript;
        bytes4 fundTxIndx;
        bytes sighash;
        bytes pkPUncompr;
        bytes pkVUncompr;
        uint256 timelock;
        uint256 timelockDisp;
        uint256 balDistr;
    }

    struct AuroraState {
        bool coinsLocked;
        bool setupDone;
        bool proofSubmitted;
        bool disputeOpened;
        bool disputeClosedP;
        bool disputeClosedV;
    }

    struct PaymentChannel {
        uint balP;
        uint balV;
        bytes32 rKey;
    }

    AuroraParam public bridge;
    AuroraState public state;
    PaymentChannel public paymentChan;

    mapping(address => uint256) initBalEth;

    address prover;
    address verifier;
    uint256 totalSupply;

    bool private _initialized;

    // -- H2: User Protection Pool (Du) ----------------------------------------
    uint256 public userProtectionPool;
    uint256 public perUserAllocation;
    bool public duLocked;
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    // -- EIP-4844: Data Availability commitment -------------------------------
    bytes32 public dataCommitment;

    // -- Registration-bound batch commitment -----------------------------------
    uint256 public constant MAX_BATCH_SIZE = 256;
    uint256 public constant MAX_LEAF_AMOUNT = 0.01 ether;
    mapping(address => uint256) public registrationIndexPlusOne;
    struct Registration {
        address user;
        uint96 amount;
        bytes32 obligationCommitment;
    }
    mapping(uint256 => Registration) public registrationAt;
    mapping(uint256 => bytes32) private registrationFrontier;
    uint256 public registeredCount;
    uint256 public registeredTotalAmount;

    bytes32 public currentMerkleRoot;
    uint256 public batchSize;
    uint256 public realBatchSize;
    uint256 public paddedBatchSize;
    uint256[] public claimBitmap;
    uint256 public claimedCount;

    bool public batchSettled;
    bool public settled;

    uint256 public constant CHALLENGE_WINDOW = 1 days;
    uint256 public constant T_CLAIM = 7 days;
    uint256 public batchSubmitTime;
    mapping(uint256 => bool) public invalidatedLeaves;
    uint256 public invalidatedCount;

    // -- Burn-to-Extend: congestion-resilient challenge window -----------------
    uint256 public constant EXTENSION_FEE = 0.05 ether;
    uint256 public constant MAX_EXTENSIONS = 3;
    uint256 public extensionCount;
    event challengeWindowExtended(uint256 newDeadline, uint256 extensionNumber);

    // -- Path 3 Freeze: arbitration window -------------------------------------
    bool public frozen;
    uint256 public frozenAt;
    uint256 public frozenAmount;
    address public arbitrator;
    bool public arbitrationDone;
    uint256 public constant ARBITRATION_TIMEOUT = 7 days;
    event DisputeFrozen(uint256 frozenAmount, uint256 frozenAt);
    event ArbitrationResolved(bool slashProver, address beneficiary, uint256 amount);

    // -- EIP-1167: lock implementation, expose initializer --------------------

    constructor() {
        _initialized = true;
    }

    function initialize(address _prover, address _verifier) external {
        require(!_initialized, "E0");
        _initialized = true;
        prover = _prover;
        verifier = _verifier;
    }

    /// @notice Prover sets the arbitrator address before submitting the Merkle root.
    function setArbitrator(address _arb) external {
        require(msg.sender == prover, "E1");
        require(currentMerkleRoot == bytes32(0), "E2");
        require(_arb != address(0), "E3");
        arbitrator = _arb;
    }

    // -- EIP-712 helpers -------------------------------------------------------

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("Aurora"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @dev EIP-712 leaf hash: 0x1901 || domainSeparator || hashStruct(AuroraLeaf)
    function _leafHash(address addr, uint256 amount, uint256 index, bytes32 obligationCommitment) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(LEAF_TYPEHASH, addr, amount, index, obligationCommitment));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    // -- Pre-commitment --------------------------------------------------------

    function registerIntent(uint256 amount, bytes32 obligationCommitment) external {
        require(currentMerkleRoot == bytes32(0), "E2");
        require(registrationIndexPlusOne[msg.sender] == 0, "E4");
        require(msg.sender != prover && msg.sender != verifier, "E49");
        require(amount > 0 && amount <= MAX_LEAF_AMOUNT, "E50");
        require(obligationCommitment != bytes32(0), "E56");
        require(registeredCount < MAX_BATCH_SIZE, "E51");
        uint256 index = registeredCount;
        registrationIndexPlusOne[msg.sender] = index + 1;
        registrationAt[index] = Registration(msg.sender, uint96(amount), obligationCommitment);
        _appendRegistrationLeaf(index, keccak256(bytes.concat(_leafHash(msg.sender, amount, index, obligationCommitment))));
        registeredCount = index + 1;
        registeredTotalAmount += amount;
        emit UserRegistered(msg.sender, index, amount, obligationCommitment);
    }

    // -- Core -----------------------------------------------------------------

    receive() external payable {
        initBalEth[msg.sender] += msg.value;
        totalSupply = totalSupply + msg.value;
        state.coinsLocked = true;
        emit lockEvent("S0", msg.sender, msg.value);
    }

    function setup(bytes32 fundTxId,
                   bytes memory fundTxScript,
                   bytes4 fundTxIndx,
                   bytes memory sighash,
                   bytes memory pkPUncompr,
                   bytes memory pkVUncompr,
                   uint256 timelock,
                   uint256 timelockDisp,
                   bytes memory sigP,
                   bytes memory sigV) external {

        bridge.fundTxId = fundTxId;
        bridge.fundTxScript = fundTxScript;
        bridge.fundTxIndx = fundTxIndx;
        bridge.sighash = sighash;
        bridge.pkPUncompr = pkPUncompr;
        bridge.pkVUncompr = pkVUncompr;
        bridge.timelock = timelock;
        bridge.timelockDisp = timelockDisp;
        bridge.balDistr = 7;

        bytes memory message = bytes.concat(BytesLib.toBytes(bridge.fundTxId), bridge.fundTxScript, BytesLib.toBytesNew(bridge.fundTxIndx), bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr, BytesLib.uint256ToBytes(bridge.timelock), BytesLib.uint256ToBytes(bridge.timelockDisp));
        require(prover == ECDSA.recover(sha256(message), abi.encodePacked(sigP)) && verifier == ECDSA.recover(sha256(message), abi.encodePacked(sigV)), "E5");

        state.proofSubmitted = false;
        state.disputeOpened = false;
        state.disputeClosedP = false;
        state.disputeClosedV = false;
        state.setupDone = true;
    }

    // -- BTC proof & dispute functions -----------------------------------------

    function submitProof(bytes memory CT_P_unlocked, bytes memory CT_V_unlocked) external {
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true &&
                                                  state.setupDone == true &&
                                                  state.proofSubmitted == false &&
                                                  state.disputeOpened == false)) {
            require(AuroraHelperExt.getTimelock(CT_P_unlocked) == bytes4(0), "E6");
            require(AuroraHelperExt.getTimelock(CT_V_unlocked) == bytes4(0), "E7");

            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh;
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = AuroraHelperExt.checkTxAreWellFormed(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);
            AuroraHelperExt.checkSignaturesEcrecover(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr);
            require(htlc[0].value > 10, "E8");

            state.proofSubmitted = true;
            emit stateEvent("S1", state.proofSubmitted);
        } else {
            emit stateEvent("S2", state.proofSubmitted);
        }
    }

    function optimisticSubmitProof(bytes memory sigP, bytes memory sigV, uint256 seqNumber) external {
        bytes32 message = sha256(bytes.concat(BytesLib.uint256ToBytes(seqNumber), abi.encodePacked("proofSubmitted"), abi.encodePacked(true)));
        if (block.timestamp < bridge.timelock && state.coinsLocked == true
                                              && state.setupDone == true
                                              && state.proofSubmitted == false
                                              && state.disputeOpened == false
                                              && prover == ECDSA.recover(message, abi.encodePacked(sigP))
                                              && verifier == ECDSA.recover(message, abi.encodePacked(sigV))) {
            state.proofSubmitted = true;
            emit stateEvent("S1", state.proofSubmitted);
        } else {
            emit stateEvent("S2", state.proofSubmitted);
        }
    }

    function dispute(bytes memory CT_P_locked, bytes memory CT_V_unlocked) external {
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true &&
                                                  state.setupDone == true &&
                                                  state.proofSubmitted == false &&
                                                  state.disputeOpened == false)) {
            require(AuroraHelperExt.getTxTimelock(CT_P_locked) > bridge.timelock + bridge.timelockDisp, "E9");
            require(AuroraHelperExt.getTxTimelock(CT_V_unlocked) == uint32(0), "E10");

            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh;
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = AuroraHelperExt.checkTxAreWellFormed(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);
            require(AuroraHelperExt.checkSignaturesEcrecover(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr) == true, "E11");
            require(htlc[0].value > 10, "E12");

            paymentChan.balP = htlc[0].value;
            paymentChan.balV = htlc[1].value;
            paymentChan.rKey = AuroraHelperExt.getRevSecret(CT_P_locked);
            state.disputeOpened = true;
            emit stateEvent("S3", state.disputeOpened);
        } else {
            emit stateEvent("S4", state.disputeOpened);
        }
    }

    function resolveValidDispute(bytes memory CT_P_unlocked) external {
        require(block.timestamp < (bridge.timelock + bridge.timelockDisp), "E13");
        require(state.coinsLocked == true && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true, "E14");
        require(AuroraHelperExt.getTimelock(CT_P_unlocked) == bytes4(0), "E6");
        require(AuroraHelperExt.getInputsData(CT_P_unlocked).txid == bridge.fundTxId, "E15");

        ParseBTCLib.HTLCData memory htlc;
        ParseBTCLib.P2PKHData memory p2pkh;
        ParseBTCLib.OpReturnData memory opreturn;
        (htlc, p2pkh, opreturn) = AuroraHelperExt.getOutputsDataLNB(CT_P_unlocked);
        require(htlc.value == paymentChan.balP, "E16");
        require(p2pkh.value == paymentChan.balV, "E17");
        AuroraHelperExt.checkSignatureEcrecover(CT_P_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkVUncompr);

        state.disputeClosedP = true;
        emit stateEvent("S5", state.disputeClosedP);
    }

    function resolveInvalidDispute(string memory revSecret) external {
        require(block.timestamp < (bridge.timelock + bridge.timelockDisp), "E13");
        require(state.coinsLocked == true && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true, "E14");
        require(paymentChan.rKey == sha256(abi.encodePacked(sha256(bytes(revSecret)))), "E18");

        state.disputeClosedV = true;
        emit stateEvent("S6", state.disputeClosedV);
    }

    // -- H2: User Protection Pool deposit -------------------------------------

    function depositUserPool() external payable {
        require(msg.sender == prover, "E19");
        require(!duLocked, "E20");
        require(state.setupDone, "E21");
        require(msg.value > 0, "E22");
        userProtectionPool += msg.value;
        emit userPoolDeposited(msg.value);
    }

    // -- Batch functions -------------------------------------------------------

    function submitMerkleRoot(
        bytes32 _merkleRoot,
        uint256 _paddedBatchSize
    ) external {
        require(msg.sender == prover, "E23");
        require(state.coinsLocked, "E24");
        require(state.setupDone, "E25");
        require(block.timestamp < bridge.timelock, "E26");
        require(state.proofSubmitted == false && state.disputeOpened == false, "E27");
        require(registeredCount > 0, "E28");
        require(_paddedBatchSize == _paddedSize(registeredCount), "E52");
        require(currentMerkleRoot == bytes32(0), "E29");
        require(userProtectionPool >= registeredTotalAmount, "E30");
        require(_merkleRoot == _accumulatorRoot(_paddedBatchSize), "E53");

        // EIP-4844: read blob commitment - leaf DA data is in the blob sidecar
        bytes32 blobCommitment = blobhash(0);
        require(blobCommitment != bytes32(0), "E31");
        dataCommitment = blobCommitment;

        // Lock Du and compute per-user allocation
        duLocked = true;
        perUserAllocation = userProtectionPool / registeredCount;

        currentMerkleRoot = _merkleRoot;
        realBatchSize = registeredCount;
        paddedBatchSize = _paddedBatchSize;
        batchSize = _paddedBatchSize;
        batchSubmitTime = block.timestamp;

        uint256 numWords = (_paddedBatchSize + 255) / 256;
        for (uint256 i = 0; i < numWords; i++) claimBitmap.push(0);

        emit batchBlobCommitted(_merkleRoot, blobCommitment, _paddedBatchSize);
        emit batchProofSubmitted(_merkleRoot, _paddedBatchSize);
    }

    function claimWithMerkleProof(
        address addr,
        uint256 amount,
        bytes32[] calldata merkleProof,
        uint256 index
    ) external {
        require(currentMerkleRoot != bytes32(0), "E32");
        require(index < realBatchSize, "E33");
        require(block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "E34");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM, "E35");
        require(!invalidatedLeaves[index], "E36");

        require(!isClaimed(index), "E38");
        require(msg.sender == addr,    "E39");
        require(registrationIndexPlusOne[addr] == index + 1, "E54");
        Registration storage registration = registrationAt[index];
        require(registration.user == addr, "E40");
        require(registration.amount == amount, "E55");
        require(addr != prover,        "E41");
        require(addr != verifier,      "E42");
        bytes32 leafHash = _leafHash(addr, amount, index, registration.obligationCommitment);
        require(verifyMerkleProof(currentMerkleRoot, leafHash, merkleProof, index), "E37");

        _setClaimed(index);
        claimedCount++;

        if (perUserAllocation > 0 && userProtectionPool >= perUserAllocation) {
            userProtectionPool -= perUserAllocation;
            (bool sent,) = payable(addr).call{value: perUserAllocation}("");
            require(sent, "E43");
            emit userPaid(index, addr, perUserAllocation);
        }

        emit leafClaimed(currentMerkleRoot, index);
    }

    function challengeLeaf(
        uint256 index,
        address addr,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external {
        require(currentMerkleRoot != bytes32(0), "E32");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "E44");
        require(index < batchSize, "E33");
        require(!invalidatedLeaves[index], "E45");
        require(!isClaimed(index), "E46");

        bytes32 leafHash = _leafHash(addr, amount, index, registrationAt[index].obligationCommitment);
        require(verifyMerkleProof(currentMerkleRoot, leafHash, merkleProof, index), "E47");
        require(amount == 0 || addr == address(0), "E48");

        invalidatedLeaves[index] = true;
        invalidatedCount++;
        emit leafChallenged(currentMerkleRoot, index, msg.sender);
    }

    /// @notice Permissionless: invalidate a leaf whose index appears twice in the batch
    ///         with two distinct pre-images, both verifiable against the committed Merkle root.
    ///         Implements Listing 2 / Theorem 3 (On-Chain Index-Uniqueness Completeness).
    function challengeDuplicateLeaf(
        uint256 index,
        address addr1, uint256 amount1, bytes32[] calldata proof1,
        address addr2, uint256 amount2, bytes32[] calldata proof2
    ) external {
        require(currentMerkleRoot != bytes32(0), "E32");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "E44");
        require(index < batchSize, "E33");
        require(!invalidatedLeaves[index], "E45");

        bytes32 leaf1 = _leafHash(addr1, amount1, index, registrationAt[index].obligationCommitment);
        bytes32 leaf2 = _leafHash(addr2, amount2, index, registrationAt[index].obligationCommitment);
        require(leaf1 != leaf2, "E64");
        require(verifyMerkleProof(currentMerkleRoot, leaf1, proof1, index), "E65");
        require(verifyMerkleProof(currentMerkleRoot, leaf2, proof2, index), "E66");

        invalidatedLeaves[index] = true;
        invalidatedCount++;
        emit leafChallenged(currentMerkleRoot, index, msg.sender);
    }

    /// @notice Verifier burns EXTENSION_FEE ETH to extend the challenge window by 1 day.
    function extendChallengeWindow() external payable {
        require(currentMerkleRoot != bytes32(0), "E32");
        require(msg.sender == verifier, "E49");
        require(extensionCount < MAX_EXTENSIONS, "E50");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "E51");
        require(msg.value == EXTENSION_FEE, "E52");
        extensionCount++;
        (bool ok,) = payable(BURN_ADDRESS).call{value: msg.value}("");
        require(ok, "E53");
        emit challengeWindowExtended(batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), extensionCount);
    }

    // -- Settle (all 6 paths) -------------------------------------------------

    function settle() external {
        require(!settled, "E54");
        settled = true;

        if (state.proofSubmitted == true || (state.disputeOpened == true && state.disputeClosedP == true)) {
            // Path 1: Fixed split of Dp+Dv; Du burned
            uint256 proverShare = (totalSupply * bridge.balDistr) / 100;
            uint256 verifierShare = totalSupply - proverShare;
            (bool sentP, ) = prover.call{value: proverShare}(""); require(sentP, "E55");
            (bool sentV, ) = verifier.call{value: verifierShare}(""); require(sentV, "E55");
            _burnRemainingDu();
            emit stateEvent("S7", true);

        } else if (currentMerkleRoot != bytes32(0) && claimedCount > 0 && block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM) {
            // Path 2: Proportional split of Dp+Dv; remaining Du burned
            uint256 proverShare = (totalSupply * claimedCount) / realBatchSize;
            uint256 verifierShare = totalSupply - proverShare;
            batchSettled = true;
            if (proverShare > 0) { (bool sentP, ) = prover.call{value: proverShare}(""); require(sentP, "E56"); }
            if (verifierShare > 0) { (bool sentV, ) = verifier.call{value: verifierShare}(""); require(sentV, "E57"); }
            _burnRemainingDu();
            emit stateEvent("S8", true);

        } else if (currentMerkleRoot != bytes32(0) && claimedCount == 0 && !state.disputeOpened) {
            // Path 2b: Zero-claim timeout; Dp+Dv refunded; Du burned
            require(block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM, "E34");
            (bool sentP, ) = prover.call{value: initBalEth[prover]}(""); require(sentP, "E56");
            (bool sentV, ) = verifier.call{value: initBalEth[verifier]}(""); require(sentV, "E57");
            _burnRemainingDu();
            emit stateEvent("S9", true);

        } else if (state.disputeOpened == true && (state.disputeClosedP == false && state.disputeClosedV == false)) {
            // Path 3: Unresolved dispute - D frozen for arbitration; Du BURNED
            frozenAmount = totalSupply;
            frozen = true;
            frozenAt = block.timestamp;
            _burnRemainingDu();
            emit DisputeFrozen(frozenAmount, frozenAt);
            emit stateEvent("S10", true);

        } else if (state.disputeOpened == true && state.disputeClosedV == true) {
            // Path 4: Revocation - Verifier gets Dp+Dv; Du burned
            (bool sentV, ) = verifier.call{value: totalSupply}(""); require(sentV, "E55");
            _burnRemainingDu();
            emit stateEvent("S11", true);

        } else if (state.coinsLocked == true && state.setupDone == false) {
            // Path 5: Setup aborted - Dp+Dv refunded
            (bool sentP, ) = prover.call{value: initBalEth[prover]}(""); require(sentP, "E55");
            (bool sentV, ) = verifier.call{value: initBalEth[verifier]}(""); require(sentV, "E55");
            _burnRemainingDu();
            emit stateEvent("S12", true);

        } else {
            settled = false;
            revert("E58");
        }
    }

    /// @notice Arbitrator resolves a frozen dispute within ARBITRATION_TIMEOUT.
    function arbitratorResolve(bool slashProver) external {
        require(frozen, "E59");
        require(!arbitrationDone, "E60");
        require(msg.sender == arbitrator, "E61");
        require(block.timestamp <= frozenAt + ARBITRATION_TIMEOUT, "E62");
        arbitrationDone = true;
        uint256 amount = frozenAmount;
        frozenAmount = 0;
        if (slashProver) {
            (bool ok,) = verifier.call{value: amount}(""); require(ok, "E55");
            emit ArbitrationResolved(true, verifier, amount);
        } else {
            (bool ok,) = prover.call{value: amount}(""); require(ok, "E55");
            emit ArbitrationResolved(false, prover, amount);
        }
    }

    /// @notice Failsafe: after ARBITRATION_TIMEOUT with no arbitrator action, burn frozen D.
    function arbitratorFinalize() external {
        require(frozen, "E59");
        require(!arbitrationDone, "E60");
        require(block.timestamp > frozenAt + ARBITRATION_TIMEOUT, "E63");
        arbitrationDone = true;
        uint256 amount = frozenAmount;
        frozenAmount = 0;
        (bool ok,) = payable(BURN_ADDRESS).call{value: amount}("");
        if (ok) emit userPoolBurned(amount);
        emit stateEvent("S13", true);
    }

    /// @dev Burns any remaining Du to prevent P+V collusion recovery.
    function _burnRemainingDu() internal {
        if (userProtectionPool > 0) {
            uint256 amount = userProtectionPool;
            userProtectionPool = 0;
            (bool ok,) = payable(BURN_ADDRESS).call{value: amount}("");
            if (ok) emit userPoolBurned(amount);
        }
    }

    // -- Helpers ---------------------------------------------------------------

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 wordIndex = index / 256;
        uint256 bitIndex = index % 256;
        if (wordIndex >= claimBitmap.length) return false;
        return (claimBitmap[wordIndex] & (1 << bitIndex)) != 0;
    }

    function _setClaimed(uint256 index) internal {
        claimBitmap[index / 256] |= (1 << (index % 256));
    }

    function _paddedSize(uint256 count) internal pure returns (uint256 padded) {
        padded = 1;
        while (padded < count) padded <<= 1;
    }

    function referenceRegistrationMerkleRoot(uint256 padded) external view returns (bytes32) {
        require(padded == _paddedSize(registeredCount), "E52");
        return _registrationMerkleRoot(padded);
    }

    function registrationAccumulatorRoot(uint256 padded) external view returns (bytes32) {
        require(padded == _paddedSize(registeredCount), "E52");
        return _accumulatorRoot(padded);
    }

    /// @dev This O(N') reducer is a validation oracle.  Sepolia submission uses
    ///      the O(1) accumulator root and keeps this reducer in the already
    ///      linked helper library to respect the EIP-170 bytecode limit.
    function _registrationMerkleRoot(uint256 padded) internal view returns (bytes32) {
        bytes32[] memory level = new bytes32[](padded);
        for (uint256 i = 0; i < padded; i++) {
            if (i < registeredCount) {
                Registration storage registration = registrationAt[i];
                level[i] = keccak256(bytes.concat(_leafHash(
                    registration.user, registration.amount, i, registration.obligationCommitment
                )));
            } else {
                level[i] = _dummyLeafNode();
            }
        }
        return AuroraHelperExt.registrationMerkleRoot(level);
    }

    function _appendRegistrationLeaf(uint256 index, bytes32 node) internal {
        uint256 count = index;
        uint256 height;
        while ((count & 1) == 1) {
            node = keccak256(abi.encodePacked(registrationFrontier[height], node));
            count >>= 1;
            height++;
        }
        registrationFrontier[height] = node;
    }

    function _accumulatorRoot(uint256 padded) internal view returns (bytes32) {
        uint256 height;
        uint256 size = padded;
        while (size > 1) { size >>= 1; height++; }
        return _frontierRoot(registeredCount, height);
    }

    function _dummyLeafNode() internal view returns (bytes32) {
        return keccak256(abi.encodePacked("AURORA_DUMMY", address(this)));
    }

    function _emptySubtree(uint256 height) internal view returns (bytes32 node) {
        node = _dummyLeafNode();
        for (uint256 i = 0; i < height; i++) node = keccak256(abi.encodePacked(node, node));
    }

    function _frontierRoot(uint256 count, uint256 height) internal view returns (bytes32) {
        if (count == 0) return _emptySubtree(height);
        if (count == (uint256(1) << height)) return registrationFrontier[height];

        uint256 half = uint256(1) << (height - 1);
        if (count > half) {
            return keccak256(abi.encodePacked(
                registrationFrontier[height - 1],
                _frontierRoot(count - half, height - 1)
            ));
        }
        return keccak256(abi.encodePacked(
            _frontierRoot(count, height - 1),
            _emptySubtree(height - 1)
        ));
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

    function getBitmapWord(uint256 wordIndex) external view returns (uint256) {
        if (wordIndex >= claimBitmap.length) return 0;
        return claimBitmap[wordIndex];
    }

    function getClaimedCount() external view returns (uint256 count) {
        for (uint256 i = 0; i < claimBitmap.length; i++) {
            uint256 word = claimBitmap[i];
            while (word != 0) { word &= (word - 1); count++; }
        }
    }
}

