// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./ParseBTCLib.sol";
import "./BytesLib.sol";
import "./BTCUtils.sol";
import "./ECDSA.sol";
import "./AuroraHelper.sol";

/**
 * @title AuroraFull
 * @dev Full Aurora contract with all logic (BTC parsing + batch + all settlement paths)
 *      and EIP-1167 proxy compatibility.
 *
 * Identical to Aurora.sol except:
 *   - constructor() locks the implementation (_initialized = true)
 *   - initialize(prover, verifier) replaces constructor args for clone pattern
 *
 * Compatible with AuroraFactory: deploy impl -> factory.createBatch(p, v) -> clone
 *
 * Settlement paths:
 *   Path 1  - submitProof (BTC) OR resolveValidDispute -> balDistr split
 *   Path 2  - batch proportional (claimedCount > 0)
 *   Path 2b - batch zero-claim timeout -> deposit refund
 *   Path 3  - dispute unresolved -> all to prover
 *   Path 4  - resolveInvalidDispute (revocation) -> all to verifier
 *   Path 5  - no setup -> deposit refund
 */
contract AuroraFull {

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
    /// @dev Du is deposited by Prover separately from Dp+Dv, locked at submitMerkleRoot,
    ///      and paid directly to users on claim. Remaining Du is burned at settle(),
    ///      making P+V collusion economically irrational (Theorem 7).
    uint256 public userProtectionPool;
    uint256 public perUserAllocation;
    bool public duLocked;
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    // -- EIP-4844: Data Availability commitment -------------------------------
    /// @dev Stores the versioned hash (blobhash(0)) of the blob sidecar submitted
    ///      alongside submitMerkleRoot. Leaf data is in the blob - no LOG3 events.
    bytes32 public dataCommitment;

    // -- Registration-bound batch commitment -----------------------------------
    /// @dev A registration fixes the only leaf that an address may claim in this
    ///      batch.  This is an eligibility and amount-binding mechanism; it does
    ///      not establish beneficial-owner independence (see the paper's bounded
    ///      affiliate-capture assumption).
    uint256 public constant MAX_BATCH_SIZE = 256;
    /// @dev Deployment calibration for the ETH-equivalent claim value cap
    ///      V_max used by the collateral model.
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
    /// @dev `batchSize` is retained as the padded Merkle size for ABI
    ///      compatibility.  Settlement and Du allocation use `realBatchSize`.
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
    /// @dev Verifier may extend the challenge window by 1 day per call by burning
    ///      EXTENSION_FEE ETH. Max MAX_EXTENSIONS extensions (3 days total extra).
    ///      Economic asymmetry: attack costs millions to sustain BTC congestion;
    ///      Verifier pays only ~$10-50 per extension on Ethereum.
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
        require(!_initialized, "Already initialized");
        _initialized = true;
        prover = _prover;
        verifier = _verifier;
    }

    /// @notice Prover sets the arbitrator address before submitting the Merkle root.
    ///         The arbitrator is a trusted multi-sig that resolves frozen disputes (Path 3).
    function setArbitrator(address _arb) external {
        require(msg.sender == prover, "Only prover can set arbitrator");
        require(currentMerkleRoot == bytes32(0), "Root already submitted");
        require(_arb != address(0), "Zero arbitrator");
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

    /// @notice Registers exactly one claimable leaf for the caller.  The amount
    ///         and sequential index are immutable once recorded, so the Prover
    ///         cannot later select a different leaf value or denominator.
    function registerIntent(uint256 amount, bytes32 obligationCommitment) external {
        require(currentMerkleRoot == bytes32(0), "Root already submitted");
        require(registrationIndexPlusOne[msg.sender] == 0, "Already registered");
        require(msg.sender != prover && msg.sender != verifier, "Operator cannot register");
        require(amount > 0 && amount <= MAX_LEAF_AMOUNT, "Amount exceeds leaf cap");
        require(obligationCommitment != bytes32(0), "Zero obligation commitment");
        require(registeredCount < MAX_BATCH_SIZE, "Batch registration capacity reached");

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
        emit lockEvent("Coins locked!", msg.sender, msg.value);
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
        require(prover == ECDSA.recover(sha256(message), abi.encodePacked(sigP)) && verifier == ECDSA.recover(sha256(message), abi.encodePacked(sigV)), "Invalid signatures over setup data");

        state.proofSubmitted = false;
        state.disputeOpened = false;
        state.disputeClosedP = false;
        state.disputeClosedV = false;
        state.setupDone = true;
    }

    // -- BTC proof & dispute functions (identical to Aurora.sol) --------------

    function submitProof(bytes memory CT_P_unlocked, bytes memory CT_V_unlocked) external {
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true &&
                                                  state.setupDone == true &&
                                                  state.proofSubmitted == false &&
                                                  state.disputeOpened == false)) {
            require(ParseBTCLib.getTimelock(CT_P_unlocked) == bytes4(0), "CTxP locked");
            require(ParseBTCLib.getTimelock(CT_V_unlocked) == bytes4(0), "CTxV locked");

            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh;
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = AuroraHelper.checkTxAreWellFormed(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);
            AuroraHelper.checkSignaturesEcrecover(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr);
            require(htlc[0].value > 10, "Prover does not have a sufficient amount of coins");

            state.proofSubmitted = true;
            emit stateEvent("Proof successfully verified", state.proofSubmitted);
        } else {
            emit stateEvent("Proof verification failed", state.proofSubmitted);
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
            emit stateEvent("Proof optimistically verified", state.proofSubmitted);
        } else {
            emit stateEvent("Proof verification failed", state.proofSubmitted);
        }
    }

    function dispute(bytes memory CT_P_locked, bytes memory CT_V_unlocked) external {
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true &&
                                                  state.setupDone == true &&
                                                  state.proofSubmitted == false &&
                                                  state.disputeOpened == false)) {
            require(ParseBTCLib.getTxTimelock(CT_P_locked) > bridge.timelock + bridge.timelockDisp, "CTxP is unlocked or its timelocked is smaller than/equal to T + T_rel");
            require(ParseBTCLib.getTxTimelock(CT_V_unlocked) == uint32(0), "CTxV is locked");

            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh;
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = AuroraHelper.checkTxAreWellFormed(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);
            require(AuroraHelper.checkSignaturesEcrecover(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr) == true, "Invalid signatures");
            require(htlc[0].value > 10, "No sufficient amount of coins");

            paymentChan.balP = htlc[0].value;
            paymentChan.balV = htlc[1].value;
            paymentChan.rKey = AuroraHelper.getRevSecret(CT_P_locked);
            state.disputeOpened = true;
            emit stateEvent("Dispute opened", state.disputeOpened);
        } else {
            emit stateEvent("Failed to open dispute", state.disputeOpened);
        }
    }

    function resolveValidDispute(bytes memory CT_P_unlocked) external {
        require(block.timestamp < (bridge.timelock + bridge.timelockDisp), "Dispute resolution window closed");
        require(state.coinsLocked == true && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true, "No active dispute to resolve");
        require(ParseBTCLib.getTimelock(CT_P_unlocked) == bytes4(0), "CTxP locked");
        require(ParseBTCLib.getInputsData(CT_P_unlocked).txid == bridge.fundTxId, "CTxP does not spend funding Tx");

        ParseBTCLib.HTLCData memory htlc;
        ParseBTCLib.P2PKHData memory p2pkh;
        ParseBTCLib.OpReturnData memory opreturn;
        (htlc, p2pkh, opreturn) = ParseBTCLib.getOutputsDataLNB(CT_P_unlocked);
        require(htlc.value == paymentChan.balP, "The value in the HTLC does not corrispond to the value in the HTLC of P's locked transaction");
        require(p2pkh.value == paymentChan.balV, "The value in the p2pkh does not corrispond to the value in the HTLC of V's unlocked transaction");
        AuroraHelper.checkSignatureEcrecover(CT_P_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkVUncompr);

        state.disputeClosedP = true;
        emit stateEvent("Valid Dispute resolved", state.disputeClosedP);
    }

    function resolveInvalidDispute(string memory revSecret) external {
        require(block.timestamp < (bridge.timelock + bridge.timelockDisp), "Dispute resolution window closed");
        require(state.coinsLocked == true && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true, "No active dispute to resolve");
        require(paymentChan.rKey == sha256(abi.encodePacked(sha256(bytes(revSecret)))), "Invalid revocation secret");

        state.disputeClosedV = true;
        emit stateEvent("Invalid Dispute resolved", state.disputeClosedV);
    }

    // -- H2: User Protection Pool deposit -------------------------------------

    /// @notice Prover deposits Du (user protection pool) before submitMerkleRoot.
    ///         Du must cover the full batch value: Du >= N * Vmax * r0 * ΔPmax * α.
    ///         Once submitMerkleRoot is called, Du is locked and cannot be withdrawn.
    function depositUserPool() external payable {
        require(msg.sender == prover, "Only prover can deposit user pool");
        require(!duLocked, "User pool already locked");
        require(state.setupDone, "Setup must be done before depositing Du");
        require(msg.value > 0, "Must deposit > 0");
        userProtectionPool += msg.value;
        emit userPoolDeposited(msg.value);
    }

    // -- Batch functions -------------------------------------------------------

    function submitMerkleRoot(
        bytes32 _merkleRoot,
        uint256 _paddedBatchSize
    ) external {
        require(msg.sender == prover, "Only prover can submit batch");
        require(state.coinsLocked, "No coins locked");
        require(state.setupDone, "Setup not done");
        require(block.timestamp < bridge.timelock, "Timelock expired");
        require(state.proofSubmitted == false && state.disputeOpened == false, "Proof or dispute already active");
        require(registeredCount > 0, "No registered obligations");
        require(_paddedBatchSize == _paddedSize(registeredCount), "Invalid padded batch size");
        require(currentMerkleRoot == bytes32(0), "Batch already submitted");
        require(userProtectionPool >= registeredTotalAmount, "User protection pool below registered value");
        require(_merkleRoot == _rootForSubmission(_paddedBatchSize), "Root does not match registrations");

        // EIP-4844: read blob commitment - leaf DA data is in the blob sidecar
        bytes32 blobCommitment = blobhash(0);
        require(blobCommitment != bytes32(0), "EIP-4844 blob required for DA");
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
        require(currentMerkleRoot != bytes32(0), "No batch submitted");
        require(index < realBatchSize, "Index is not a claimable obligation");
        require(block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "Challenge window still open");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM, "Claim window expired");
        require(!invalidatedLeaves[index], "Leaf has been invalidated by challenge");

        require(!isClaimed(index), "Already claimed");
        require(msg.sender == addr,    "Must claim own leaf");
        require(registrationIndexPlusOne[addr] == index + 1, "Leaf index not bound to registration");
        Registration storage registration = registrationAt[index];
        require(registration.user == addr, "Addr not pre-registered");
        require(registration.amount == amount, "Leaf amount not bound to registration");
        require(addr != prover,        "Prover cannot receive Du");
        require(addr != verifier,      "Verifier cannot receive Du");
        bytes32 leafHash = _leafHash(addr, amount, index, registration.obligationCommitment);
        require(verifyMerkleProof(currentMerkleRoot, leafHash, merkleProof, index), "Invalid Merkle proof");

        _setClaimed(index);
        claimedCount++;

        if (perUserAllocation > 0 && userProtectionPool >= perUserAllocation) {
            userProtectionPool -= perUserAllocation;
            (bool sent,) = payable(addr).call{value: perUserAllocation}("");
            require(sent, "User ETH transfer failed");
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
        require(currentMerkleRoot != bytes32(0), "No batch submitted");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "Challenge window closed");
        require(index < batchSize, "Index out of bounds");
        require(!invalidatedLeaves[index], "Leaf already invalidated");
        require(!isClaimed(index), "Leaf already claimed");

        bytes32 leafHash = _leafHash(addr, amount, index, registrationAt[index].obligationCommitment);
        require(verifyMerkleProof(currentMerkleRoot, leafHash, merkleProof, index), "Leaf data does not match Merkle tree");
        require(amount == 0 || addr == address(0), "Leaf is structurally valid, challenge rejected");

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
        require(currentMerkleRoot != bytes32(0), "No batch submitted");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "Challenge window closed");
        require(index < batchSize, "Index out of bounds");
        require(!invalidatedLeaves[index], "Leaf already invalidated");

        bytes32 leaf1 = _leafHash(addr1, amount1, index, registrationAt[index].obligationCommitment);
        bytes32 leaf2 = _leafHash(addr2, amount2, index, registrationAt[index].obligationCommitment);
        require(leaf1 != leaf2, "Leaves are identical: not a duplicate");
        require(verifyMerkleProof(currentMerkleRoot, leaf1, proof1, index), "Proof1 invalid");
        require(verifyMerkleProof(currentMerkleRoot, leaf2, proof2, index), "Proof2 invalid");

        invalidatedLeaves[index] = true;
        invalidatedCount++;
        emit leafChallenged(currentMerkleRoot, index, msg.sender);
    }

    /// @notice Verifier burns EXTENSION_FEE ETH to extend the challenge window by 1 day.
    ///         Can be called at most MAX_EXTENSIONS times. Fee is burned immediately.
    ///         Provides economic asymmetry: sustaining BTC congestion costs millions USD/day
    ///         while each extension costs Verifier only ~$10-50 in ETH gas + fee.
    function extendChallengeWindow() external payable {
        require(currentMerkleRoot != bytes32(0), "No batch submitted");
        require(msg.sender == verifier, "Only verifier can extend");
        require(extensionCount < MAX_EXTENSIONS, "Maximum extensions reached");
        require(block.timestamp <= batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), "Challenge window already closed");
        require(msg.value == EXTENSION_FEE, "Must burn exactly EXTENSION_FEE");
        extensionCount++;
        (bool ok,) = payable(BURN_ADDRESS).call{value: msg.value}("");
        require(ok, "Burn failed");
        emit challengeWindowExtended(batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days), extensionCount);
    }

    // -- Settle (all 6 paths, identical to Aurora.sol) ------------------------

    function settle() external {
        require(!settled, "Already settled");
        settled = true;

        if (state.proofSubmitted == true || (state.disputeOpened == true && state.disputeClosedP == true)) {
            // Path 1: Fixed split of Dp+Dv; Du burned (users already paid or not yet claimed)
            uint256 proverShare = (totalSupply * bridge.balDistr) / 100;
            uint256 verifierShare = totalSupply - proverShare;
            (bool sentP, ) = prover.call{value: proverShare}(""); require(sentP, "Failed to send ETH");
            (bool sentV, ) = verifier.call{value: verifierShare}(""); require(sentV, "Failed to send ETH");
            _burnRemainingDu();
            emit stateEvent("Valid proof submitted and funds distributed", true);

        } else if (currentMerkleRoot != bytes32(0) && claimedCount > 0 && block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM) {
            // Path 2: Proportional split of Dp+Dv; remaining Du burned
            uint256 proverShare = (totalSupply * claimedCount) / realBatchSize;
            uint256 verifierShare = totalSupply - proverShare;
            batchSettled = true;
            if (proverShare > 0) { (bool sentP, ) = prover.call{value: proverShare}(""); require(sentP, "Failed to send ETH to prover"); }
            if (verifierShare > 0) { (bool sentV, ) = verifier.call{value: verifierShare}(""); require(sentV, "Failed to send ETH to verifier"); }
            _burnRemainingDu();
            emit stateEvent("Batch settled proportionally", true);

        } else if (currentMerkleRoot != bytes32(0) && claimedCount == 0 && !state.disputeOpened) {
            // Path 2b: Zero-claim timeout; Dp+Dv refunded; Du burned
            require(block.timestamp > batchSubmitTime + CHALLENGE_WINDOW + (extensionCount * 1 days) + T_CLAIM, "Claim window still open");
            (bool sentP, ) = prover.call{value: initBalEth[prover]}(""); require(sentP, "Failed to send ETH to prover");
            (bool sentV, ) = verifier.call{value: initBalEth[verifier]}(""); require(sentV, "Failed to send ETH to verifier");
            _burnRemainingDu();
            emit stateEvent("Zero-claim timeout: deposits refunded", true);

        } else if (state.disputeOpened == true && (state.disputeClosedP == false && state.disputeClosedV == false)) {
            // Path 3: Unresolved dispute - D frozen for arbitration; Du BURNED (collusion resistance)
            // Arbitrator has ARBITRATION_TIMEOUT to call arbitratorResolve(); else arbitratorFinalize() burns D.
            frozenAmount = totalSupply;
            frozen = true;
            frozenAt = block.timestamp;
            _burnRemainingDu();
            emit DisputeFrozen(frozenAmount, frozenAt);
            emit stateEvent("Dispute unresolved: D frozen for arbitration", true);

        } else if (state.disputeOpened == true && state.disputeClosedV == true) {
            // Path 4: Revocation - Verifier gets Dp+Dv; Du burned
            (bool sentV, ) = verifier.call{value: totalSupply}(""); require(sentV, "Failed to send ETH");
            _burnRemainingDu();
            emit stateEvent("All funds given to V", true);

        } else if (state.coinsLocked == true && state.setupDone == false) {
            // Path 5: Setup aborted - Dp+Dv refunded; Du not yet deposited (duLocked=false)
            (bool sentP, ) = prover.call{value: initBalEth[prover]}(""); require(sentP, "Failed to send ETH");
            (bool sentV, ) = verifier.call{value: initBalEth[verifier]}(""); require(sentV, "Failed to send ETH");
            _burnRemainingDu();
            emit stateEvent("Funds distributed", true);

        } else {
            settled = false;
            revert("No valid settlement condition met");
        }
    }

    /// @notice Arbitrator resolves a frozen dispute within ARBITRATION_TIMEOUT.
    ///         slashProver=true  -> Verifier wins: send D to verifier (prover was fraudulent).
    ///         slashProver=false -> Prover wins:   send D to prover  (dispute was unfounded).
    function arbitratorResolve(bool slashProver) external {
        require(frozen, "Not frozen");
        require(!arbitrationDone, "Arbitration already done");
        require(msg.sender == arbitrator, "Only arbitrator");
        require(block.timestamp <= frozenAt + ARBITRATION_TIMEOUT, "Arbitration window expired");
        arbitrationDone = true;
        uint256 amount = frozenAmount;
        frozenAmount = 0;
        if (slashProver) {
            (bool ok,) = verifier.call{value: amount}(""); require(ok, "Failed to send ETH");
            emit ArbitrationResolved(true, verifier, amount);
        } else {
            (bool ok,) = prover.call{value: amount}(""); require(ok, "Failed to send ETH");
            emit ArbitrationResolved(false, prover, amount);
        }
    }

    /// @notice Failsafe: after ARBITRATION_TIMEOUT with no arbitrator action, burn frozen D.
    ///         Anyone can call this to finalize the frozen state.
    function arbitratorFinalize() external {
        require(frozen, "Not frozen");
        require(!arbitrationDone, "Arbitration already done");
        require(block.timestamp > frozenAt + ARBITRATION_TIMEOUT, "Arbitration window still open");
        arbitrationDone = true;
        uint256 amount = frozenAmount;
        frozenAmount = 0;
        (bool ok,) = payable(BURN_ADDRESS).call{value: amount}("");
        if (ok) emit userPoolBurned(amount);
        emit stateEvent("Frozen D burned: arbitration timeout", true);
    }

    /// @dev Burns any remaining Du (user protection pool) to prevent P+V collusion recovery.
    ///      Called at the end of every settlement path.
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

    /// @dev Returns the smallest power of two able to contain every registered
    ///      obligation.  Any remaining positions are fixed `(address(0), 0)`
    ///      dummy leaves and cannot be claimed.
    function _paddedSize(uint256 count) internal pure returns (uint256 padded) {
        padded = 1;
        while (padded < count) padded <<= 1;
    }

    /// @notice Reference implementation used by differential tests and the R2
    ///         benchmark oracle.  Production submission uses the cached
    ///         accumulator root below, not this O(N') reducer.
    function referenceRegistrationMerkleRoot(uint256 padded) external view returns (bytes32) {
        require(padded == _paddedSize(registeredCount), "Invalid padded batch size");
        return _registrationMerkleRoot(padded);
    }

    /// @notice Returns the incremental accumulator root for the same padded
    ///         size.  It must equal referenceRegistrationMerkleRoot(padded).
    function registrationAccumulatorRoot(uint256 padded) external view returns (bytes32) {
        require(padded == _paddedSize(registeredCount), "Invalid padded batch size");
        return _accumulatorRoot(padded);
    }

    /// @dev Rebuilds the indexed Merkle root from the immutable registration
    ///      ledger.  This reference oracle is deliberately O(N') and is never
    ///      called by submitMerkleRoot.
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

        uint256 width = padded;
        while (width > 1) {
            for (uint256 i = 0; i < width; i += 2) {
                level[i / 2] = keccak256(abi.encodePacked(level[i], level[i + 1]));
            }
            width /= 2;
        }
        return level[0];
    }

    /// @dev Binary-carry Merkle frontier.  A registration writes one peak; any
    ///      occupied lower peaks are folded in memory, making registration
    ///      storage O(1) amortized rather than writing the entire root path.
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

    /// @dev Production uses the frontier.  AuroraFullReference overrides this
    ///      hook so differential benchmarks exercise an O(N') submission path
    ///      against the identical immutable registration ledger.
    function _rootForSubmission(uint256 padded) internal view virtual returns (bytes32) {
        return _accumulatorRoot(padded);
    }

    function _dummyLeafNode() internal view returns (bytes32) {
        return keccak256(abi.encodePacked("AURORA_DUMMY", address(this)));
    }

    function _emptySubtree(uint256 height) internal view returns (bytes32 node) {
        node = _dummyLeafNode();
        for (uint256 i = 0; i < height; i++) node = keccak256(abi.encodePacked(node, node));
    }

    /// @dev Reconstructs the left-aligned padded root from the binary peaks.
    ///      Recursion depth is at most eight because MAX_BATCH_SIZE is 256.
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

