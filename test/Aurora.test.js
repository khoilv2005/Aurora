const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const EthCrypto = require('eth-crypto');
const crypto = require('crypto');

describe("AuroraFull - Bitmap Accumulator Optimization", function() {
    let testdata;
    let proverAddress, verifierAddress;
    let identityP, identityV;
    let deployer;
    let auroraImpl, auroraFactory;

    // Challenge window = 1 day in seconds
    const CHALLENGE_WINDOW = 86400;

    before(async () => {
        testdata = require("../data/jsonTestData.json");
        [deployer] = await ethers.getSigners();

        const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
        identityP = EthCrypto.createIdentity(entropyP);
        proverAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityP.privateKey));

        const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
        identityV = EthCrypto.createIdentity(entropyV);
        verifierAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityV.privateKey));

        const ImplFactory = await ethers.getContractFactory("AuroraFull");
        auroraImpl = await ImplFactory.deploy();
        await auroraImpl.deployed();

        const FactoryFactory = await ethers.getContractFactory("AuroraFactory");
        auroraFactory = await FactoryFactory.deploy(auroraImpl.address);
        await auroraFactory.deployed();
    });

    async function impersonateAndExecute(address, executeFn) {
        await network.provider.send("hardhat_setBalance", [address, "0x1000000000000000000"]);
        await network.provider.request({ method: "hardhat_impersonateAccount", params: [address] });
        const signer = await ethers.getSigner(address);
        try { await executeFn(signer); }
        finally { await network.provider.request({ method: "hardhat_stopImpersonatingAccount", params: [address] }); }
    }

    async function doSetup(contract) {
        const digest = testdata.setupMessageDigest;
        const signatureP = EthCrypto.sign(identityP.privateKey, digest);
        const signatureV = EthCrypto.sign(identityV.privateKey, digest);
        await contract.setup(
            testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex,
            testdata.sighash_all, testdata.pkProverUnprefixedUncompressed,
            testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock,
            signatureP, signatureV
        );
        // H2: deposit Du (user protection pool) - 2 ETH covers any batch size used in tests
        await impersonateAndExecute(proverAddress, async (proverSigner) => {
            await contract.connect(proverSigner).depositUserPool({
                value: ethers.utils.parseEther("2")
            });
        });
        // Fix A: register deployer as the leaf beneficiary (deployer != prover != verifier)
        await contract.connect(deployer).registerIntent();
        // Path 3 Freeze: set deployer as arbitrator for test purposes
        await impersonateAndExecute(proverAddress, async (proverSigner) => {
            await contract.connect(proverSigner).setArbitrator(deployer.address);
        });
    }

    async function claimLeaf(contract, addr, amount, proof, index) {
        // addr is deployer.address in E2E tests - deployer is an ethers signer, no impersonation needed
        await contract.connect(deployer).claimWithMerkleProof(addr, amount, proof, index);
    }

    async function deployFreshContract() {
        const tx = await auroraFactory.createBatch(proverAddress, verifierAddress);
        const receipt = await tx.wait();
        const event = receipt.events.find(e => e.event === "BatchCreated");
        const contract = await ethers.getContractAt("AuroraFull", event.args.batch);
        await deployer.sendTransaction({ to: contract.address, value: ethers.utils.parseEther("1") });
        return contract;
    }

    // ====== MERKLE TREE HELPERS (EIP-712) ======

    const CHAIN_ID = 31337; // Hardhat default
    const LEAF_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index)")
    );
    const DOMAIN_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )
    );

    function getDomainSeparator(contractAddr) {
        return ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["bytes32", "bytes32", "bytes32", "uint256", "address"],
                [
                    DOMAIN_TYPEHASH,
                    ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
                    ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")),
                    CHAIN_ID,
                    contractAddr,
                ]
            )
        );
    }

    function leafHash712(contractAddr, addr, amount, index) {
        const ds = getDomainSeparator(contractAddr);
        const structHash = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["bytes32", "address", "uint256", "uint256"],
                [LEAF_TYPEHASH, addr, ethers.BigNumber.from(amount), index]
            )
        );
        return ethers.utils.keccak256(
            ethers.utils.concat([
                ethers.utils.arrayify("0x1901"),
                ethers.utils.arrayify(ds),
                ethers.utils.arrayify(structHash),
            ])
        );
    }

    function hashPair(a, b) { return ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32", "bytes32"], [a, b])); }

    function buildMerkleTree(contractAddr, addrs, amounts) {
        // Merkle leaf node = keccak256(eip712Digest) - mirrors verifyMerkleProof on-chain
        let currentLevel = addrs.map((addr, i) => {
            const leaf = leafHash712(contractAddr, addr, amounts[i], i);
            return ethers.utils.keccak256(leaf);
        });
        const tree = [currentLevel.slice()];
        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                if (i + 1 < currentLevel.length) {
                    nextLevel.push(hashPair(currentLevel[i], currentLevel[i + 1]));
                } else {
                    nextLevel.push(currentLevel[i]);
                }
            }
            tree.push(nextLevel);
            currentLevel = nextLevel;
        }
        return { root: currentLevel[0], tree };
    }

    function getMerkleProof(tree, index) {
        const proof = [];
        let idx = index;
        for (let level = 0; level < tree.length - 1; level++) {
            const levelNodes = tree[level];
            const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
            if (siblingIdx < levelNodes.length) proof.push(levelNodes[siblingIdx]);
            idx = Math.floor(idx / 2);
        }
        return proof;
    }

    // ====== EIP-4844 blob helpers ======

    let _kzg;
    async function getKZG() {
        if (!_kzg) {
            const { loadKZG } = require("kzg-wasm");
            _kzg = await loadKZG();
        }
        return _kzg;
    }

    function buildBlobData(addrs, amounts) {
        const blob = new Uint8Array(131072); // 4096 fields × 32 bytes
        let offset = 0;
        for (let i = 0; i < addrs.length && offset + 96 <= 131072; i++) {
            blob.set(ethers.utils.arrayify(ethers.utils.hexZeroPad(addrs[i], 32)), offset); offset += 32;
            blob.set(ethers.utils.arrayify(ethers.utils.hexZeroPad(ethers.BigNumber.from(amounts[i]).toHexString(), 32)), offset); offset += 32;
            blob.set(ethers.utils.arrayify(ethers.utils.hexZeroPad(ethers.BigNumber.from(i).toHexString(), 32)), offset); offset += 32;
        }
        return blob;
    }

    // Send submitMerkleRoot as an EIP-4844 type-3 blob transaction (required by contract).
    async function submitMerkleRootWithBlob(contract, root, batchSize, addrs, amounts) {
        const { BlobEIP4844Transaction } = require("@ethereumjs/tx");
        const { Common } = require("@ethereumjs/common");
        const kzg = await getKZG();
        const blob = buildBlobData(addrs, amounts);
        const commitment = kzg.blobToKzgCommitment(blob);
        const kzgProof   = kzg.computeBlobKzgProof(blob, commitment);
        const sha256 = crypto.createHash("sha256").update(Buffer.from(commitment)).digest();
        sha256[0] = 0x01;
        const versionedHash = Uint8Array.from(sha256);
        const wallet = new ethers.Wallet(identityP.privateKey);
        await network.provider.send("hardhat_setBalance", [wallet.address, "0x100000000000000000000"]);
        const nonce = await ethers.provider.getTransactionCount(wallet.address);
        const block = await ethers.provider.getBlock("latest");
        const baseFee = block.baseFeePerGas ? BigInt(block.baseFeePerGas.toString()) : 1_000_000_000n;
        const calldata = contract.interface.encodeFunctionData("submitMerkleRoot", [root, batchSize]);
        const kzgWrapper = {
            blobToKzgCommitment:     (b)          => kzg.blobToKzgCommitment(b),
            computeBlobKzgProof:     (b, c)       => kzg.computeBlobKzgProof(b, c),
            verifyKzgProof:          (c, z, y, p) => kzg.verifyKzgProof(c, z, y, p),
            verifyBlobKzgProofBatch: (bs, cs, ps) => kzg.verifyBlobKzgProofBatch(bs, cs, ps),
        };
        const common = Common.custom(
            { chainId: 31337, name: "hardhat", networkId: 31337 },
            { hardfork: "cancun", customCrypto: { kzg: kzgWrapper } }
        );
        const tx = BlobEIP4844Transaction.fromTxData({
            nonce:                BigInt(nonce),
            maxFeePerGas:         baseFee * 2n + 1_000_000_000n,
            maxPriorityFeePerGas: 1_000_000_000n,
            gasLimit:             3_000_000n,
            to:                   contract.address.toLowerCase(),
            data:                 ethers.utils.arrayify(calldata),
            maxFeePerBlobGas:     1_000_000_000n,
            blobVersionedHashes:  [versionedHash],
            blobs:                [blob],
            kzgCommitments:       [commitment],
            kzgProofs:            [kzgProof],
        }, { common });
        const privKeyBuf = Buffer.from(identityP.privateKey.replace("0x", ""), "hex");
        const signedTx   = tx.sign(privKeyBuf);
        const rawHex     = "0x" + Buffer.from(signedTx.serializeNetworkWrapper()).toString("hex");
        const txHash = await ethers.provider.send("eth_sendRawTransaction", [rawHex]);
        await network.provider.send("evm_mine", []);
        return ethers.provider.getTransactionReceipt(txHash);
    }

    // ====== submitMerkleRoot guards ======

    describe("submitMerkleRoot Guards", function () {
        let contract;
        beforeEach(async () => { contract = await deployFreshContract(); });

        it("Should revert if setup not done", async function () {
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));
            await impersonateAndExecute(proverAddress, async (prover) => {
                await expect(contract.connect(prover).submitMerkleRoot(root, 10))
                    .to.be.revertedWith("Setup not done");
            });
        });

        it("Should revert if timelock expired", async function () {
            await doSetup(contract);
            const snapshotId = await network.provider.send("evm_snapshot");
            await network.provider.send("evm_setNextBlockTimestamp", [1701817201]);
            await network.provider.send("evm_mine");
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));
            await impersonateAndExecute(proverAddress, async (prover) => {
                await expect(contract.connect(prover).submitMerkleRoot(root, 10))
                    .to.be.revertedWith("Timelock expired");
            });
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should revert if caller is not prover", async function () {
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));
            await expect(contract.connect(deployer).submitMerkleRoot(root, 10))
                .to.be.revertedWith("Only prover can submit batch");
        });

        it("Should revert if batch already submitted", async function () {
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("batch1"));
            await submitMerkleRootWithBlob(contract, root, 8, [], []);
            const root2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("batch2"));
            // "Batch already submitted" check fires before blob check, so no blob needed
            await impersonateAndExecute(proverAddress, async (prover) => {
                await expect(contract.connect(prover).submitMerkleRoot(root2, 16))
                    .to.be.revertedWith("Batch already submitted");
            });
        });

        it("Should revert if batch size is not a power of two", async function () {
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("test"));
            for (const bad of [3, 5, 6, 7, 10, 100, 500]) {
                await impersonateAndExecute(proverAddress, async (prover) => {
                    await expect(contract.connect(prover).submitMerkleRoot(root, bad))
                        .to.be.revertedWith("Batch size must be a power of two");
                });
            }
        });

        it("Should accept valid power-of-two batch sizes", async function () {
            for (const good of [1, 2, 4, 8, 16, 128, 256]) {
                const c = await deployFreshContract();
                await doSetup(c);
                const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`batch_${good}`));
                await submitMerkleRootWithBlob(c, root, good, [], []);
                expect(await c.batchSize()).to.equal(good);
            }
        });
    });

    // ====== Blob DA Commitment ======

    describe("Blob DA Commitment", function () {
        it("Should store blob commitment and set merkle root on submitMerkleRoot", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("da_test"));
            await submitMerkleRootWithBlob(contract, root, 4, [], []);
            expect(await contract.currentMerkleRoot()).to.equal(root);
            expect(await contract.batchSize()).to.equal(4);
            // dataCommitment is the KZG versioned hash from the blob sidecar (non-zero)
            expect(await contract.dataCommitment()).to.not.equal(ethers.constants.HashZero);
        });
    });

    // ====== Bitmap Basics ======

    describe("Bitmap Basics", function () {
        it("Should submit merkle root and initialize bitmap", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("batch_500"));
            await submitMerkleRootWithBlob(contract, root, 512, [], []);
            expect(await contract.currentMerkleRoot()).to.equal(root);
            expect(await contract.batchSize()).to.equal(512);
            expect(await contract.getBitmapWord(0)).to.equal(0);
        });

        it("Should correctly calculate bitmap size for different batch sizes", async function () {
            const testCases = [
                { size: 128, expectedWords: 1 },
                { size: 256, expectedWords: 1 },
                { size: 512, expectedWords: 2 },
            ];
            for (const tc of testCases) {
                const contract = await deployFreshContract();
                await doSetup(contract);
                const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`batch_${tc.size}`));
                await submitMerkleRootWithBlob(contract, root, tc.size, [], []);
                expect(await contract.getBitmapWord(tc.expectedWords - 1)).to.equal(0);
            }
        });
    });

    // ====== End-to-End Merkle Claim Tests (uses time advancement) ======

    describe("Merkle Proof Claim - End to End", function () {
        const BATCH_SIZE = 4;

        async function setupMerkleBatch() {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [], amounts = [];
            for (let i = 0; i < BATCH_SIZE; i++) {
                addrs.push(deployer.address);
                amounts.push(ethers.utils.parseEther("0.25"));
            }
            const merkleData = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, merkleData.root, BATCH_SIZE, addrs, amounts);
            return { contract, merkleData, addrs, amounts };
        }

        it("Should claim a leaf with valid Merkle proof", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const proof = getMerkleProof(merkleData.tree, 0);
            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), proof, 0);
            expect(await contract.isClaimed(0)).to.equal(true);
            expect(await contract.claimedCount()).to.equal(1);

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should claim multiple leaves independently", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            for (let i = 0; i < BATCH_SIZE; i++) {
                await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, i), i);
                expect(await contract.isClaimed(i)).to.equal(true);
            }
            expect(await contract.claimedCount()).to.equal(BATCH_SIZE);

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject double-claim at the same index", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const proof = getMerkleProof(merkleData.tree, 0);
            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), proof, 0);
            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), proof, 0)).to.be.revertedWith("Already claimed");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject invalid Merkle proof", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const wrongProof = getMerkleProof(merkleData.tree, 1);
            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), wrongProof, 0)).to.be.revertedWith("Invalid Merkle proof");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject index out of bounds", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const proof = getMerkleProof(merkleData.tree, 0);
            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), proof, BATCH_SIZE + 10)).to.be.revertedWith("Index out of bounds");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject forged leaf data (second preimage protection)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            // Pass bogus addr/amount/index - the contract computes the hash on-chain,
            // so this will produce a different leaf hash and fail Merkle verification.
            await expect(contract.connect(deployer).claimWithMerkleProof(ethers.constants.AddressZero, 999, [], 0)).to.be.revertedWith("Invalid Merkle proof");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject claim during challenge window", async function () {
            const { contract, merkleData } = await setupMerkleBatch();
            // Do NOT advance time
            const proof = getMerkleProof(merkleData.tree, 0);
            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), proof, 0)).to.be.revertedWith("Challenge window still open");
        });

        it("Should reject claim after claim window expires", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            const proof = getMerkleProof(merkleData.tree, 0);

            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + (7 * 86400) + 60]);
            await network.provider.send("evm_mine");

            await expect(
                contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), proof, 0)
            ).to.be.revertedWith("Claim window expired");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject claim for invalidated leaf", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);

            const addrs = [deployer.address, deployer.address];
            const amounts = [ethers.utils.parseEther("0.25"), 0]; // second leaf invalid
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 2, addrs, amounts);

            // Challenge the invalid leaf (amount=0) - now requires Merkle proof
            const challengeProof = getMerkleProof(md.tree, 1);
            await contract.challengeLeaf(1, deployer.address, 0, challengeProof);

            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const proof = getMerkleProof(md.tree, 1);
            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, 0, proof, 1)).to.be.revertedWith("Leaf has been invalidated by challenge");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should emit leafClaimed event on successful claim", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            await expect(contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, 2), 2))
                .to.emit(contract, "leafClaimed").withArgs(merkleData.root, 2);

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should show claim gas cost", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupMerkleBatch();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            const tx = await contract.connect(deployer).claimWithMerkleProof(deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, 0), 0);
            const receipt = await tx.wait();
            console.log("\n=== Claim Gas Cost ===");
            console.log("claimWithMerkleProof:", receipt.gasUsed.toString(), "gas");
            console.log("======================\n");

            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ====== Challenge Mechanism Tests ======

    describe("Challenge Mechanism", function () {
        it("Should allow challenge during window", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [ethers.constants.AddressZero];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            const challengeProof = getMerkleProof(md.tree, 0);
            await expect(contract.challengeLeaf(0, ethers.constants.AddressZero, 100, challengeProof))
                .to.emit(contract, "leafChallenged");
            expect(await contract.invalidatedLeaves(0)).to.equal(true);
            expect(await contract.invalidatedCount()).to.equal(1);
        });

        it("Should reject challenge after window closes", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [ethers.constants.AddressZero];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");
            const challengeProof = getMerkleProof(md.tree, 0);
            await expect(contract.challengeLeaf(0, ethers.constants.AddressZero, 100, challengeProof))
                .to.be.revertedWith("Challenge window closed");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should reject challenge for already invalidated leaf", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [ethers.constants.AddressZero];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            const challengeProof = getMerkleProof(md.tree, 0);
            await contract.challengeLeaf(0, ethers.constants.AddressZero, 100, challengeProof);
            await expect(contract.challengeLeaf(0, ethers.constants.AddressZero, 100, challengeProof))
                .to.be.revertedWith("Leaf already invalidated");
        });
    });

    // ====== challengeDuplicateLeaf Tests ======

    describe("challengeDuplicateLeaf", function () {
        it("should revert when leaves are identical (same addr/amount)", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addr2 = ethers.utils.getAddress("0x1234567890123456789012345678901234567890");
            const addrs = [deployer.address, addr2];
            const amounts = [100, 200];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 2, addrs, amounts);
            const proof0 = getMerkleProof(md.tree, 0);
            // Same pre-image for both -> leaf1 == leaf2 -> must revert
            await expect(contract.challengeDuplicateLeaf(
                0,
                deployer.address, 100, proof0,
                deployer.address, 100, proof0
            )).to.be.revertedWith("Leaves are identical: not a duplicate");
        });

        it("should revert when challenge window is closed", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [deployer.address];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");
            const proof0 = getMerkleProof(md.tree, 0);
            await expect(contract.challengeDuplicateLeaf(
                0,
                deployer.address, 100, proof0,
                deployer.address, 200, proof0
            )).to.be.revertedWith("Challenge window closed");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("should revert when index is out of bounds", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [deployer.address];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            const proof0 = getMerkleProof(md.tree, 0);
            await expect(contract.challengeDuplicateLeaf(
                99,
                deployer.address, 100, proof0,
                deployer.address, 200, proof0
            )).to.be.revertedWith("Index out of bounds");
        });

        it("should revert when leaf is already invalidated", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [ethers.constants.AddressZero];
            const amounts = [100];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 1, addrs, amounts);
            const proof0 = getMerkleProof(md.tree, 0);
            // First invalidate via challengeLeaf
            await contract.challengeLeaf(0, ethers.constants.AddressZero, 100, proof0);
            await expect(contract.challengeDuplicateLeaf(
                0,
                ethers.constants.AddressZero, 100, proof0,
                deployer.address, 200, proof0
            )).to.be.revertedWith("Leaf already invalidated");
        });

        it("should revert when proof1 is invalid", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addr2 = ethers.utils.getAddress("0x1234567890123456789012345678901234567890");
            const addrs = [deployer.address, addr2];
            const amounts = [100, 200];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 2, addrs, amounts);
            const proof0 = getMerkleProof(md.tree, 0);
            const badProof = [ethers.constants.HashZero];
            await expect(contract.challengeDuplicateLeaf(
                0,
                deployer.address, 100, badProof,
                deployer.address, 200, proof0
            )).to.be.revertedWith("Proof1 invalid");
        });

        it("should revert when proof2 is invalid", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addr2 = ethers.utils.getAddress("0x1234567890123456789012345678901234567890");
            const addrs = [deployer.address, addr2];
            const amounts = [100, 200];
            const md = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, md.root, 2, addrs, amounts);
            const proof0 = getMerkleProof(md.tree, 0);
            const badProof = [ethers.constants.HashZero];
            await expect(contract.challengeDuplicateLeaf(
                0,
                deployer.address, 100, proof0,
                deployer.address, 200, badProof
            )).to.be.revertedWith("Proof2 invalid");
        });
    });

    // ====== Proportional Settlement Tests ======

    describe("Proportional Settlement", function () {
        const BATCH_SIZE = 4;

        async function setupSettlement() {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const addrs = [], amounts = [];
            for (let i = 0; i < BATCH_SIZE; i++) {
                addrs.push(deployer.address);
                amounts.push(ethers.utils.parseEther("0.25"));
            }
            const merkleData = buildMerkleTree(contract.address, addrs, amounts);
            await submitMerkleRootWithBlob(contract, merkleData.root, BATCH_SIZE, addrs, amounts);
            return { contract, merkleData, addrs, amounts };
        }

        it("Should settle proportionally after partial claims (50%)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupSettlement();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            for (let i = 0; i < 2; i++) {
                await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, i), i);
            }
            expect(await contract.claimedCount()).to.equal(2);

            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            const pBal = await ethers.provider.getBalance(proverAddress);
            const vBal = await ethers.provider.getBalance(verifierAddress);
            await contract.settle();
            const pGain = (await ethers.provider.getBalance(proverAddress)).sub(pBal);
            const vGain = (await ethers.provider.getBalance(verifierAddress)).sub(vBal);
            expect(pGain).to.equal(ethers.utils.parseEther("0.5"));
            expect(vGain).to.equal(ethers.utils.parseEther("0.5"));

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should settle proportionally after full claims (100%)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupSettlement();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            for (let i = 0; i < BATCH_SIZE; i++) {
                await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, i), i);
            }

            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            const pBal = await ethers.provider.getBalance(proverAddress);
            const vBal = await ethers.provider.getBalance(verifierAddress);
            await contract.settle();
            const pGain = (await ethers.provider.getBalance(proverAddress)).sub(pBal);
            const vGain = (await ethers.provider.getBalance(verifierAddress)).sub(vBal);
            expect(pGain).to.equal(ethers.utils.parseEther("1.0"));
            expect(vGain).to.equal(ethers.utils.parseEther("0"));

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should settle proportionally after single claim (25%)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupSettlement();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, 0), 0);

            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            const pBal = await ethers.provider.getBalance(proverAddress);
            const vBal = await ethers.provider.getBalance(verifierAddress);
            await contract.settle();
            const pGain = (await ethers.provider.getBalance(proverAddress)).sub(pBal);
            const vGain = (await ethers.provider.getBalance(verifierAddress)).sub(vBal);
            expect(pGain).to.equal(ethers.utils.parseEther("0.25"));
            expect(vGain).to.equal(ethers.utils.parseEther("0.75"));

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should emit batch settlement event", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupSettlement();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, 0), 0);
            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            await expect(contract.settle()).to.emit(contract, "stateEvent").withArgs("Batch settled proportionally", true);

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should prevent double-settlement of batch", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const { contract, merkleData } = await setupSettlement();
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.25"), getMerkleProof(merkleData.tree, 0), 0);
            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            await contract.settle();
            expect(await contract.batchSettled()).to.equal(true);

            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ====== Gas Analysis ======

    describe("Gas Analysis", function () {
        it("Should show efficient merkle root submission (EIP-4844 blob DA)", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const batchSize = 128;
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("gas_test"));
            const receipt = await submitMerkleRootWithBlob(contract, root, batchSize, [], []);
            console.log("\n=== Aurora Gas (EIP-4844 blob DA) ===");
            console.log("Submit merkle root (128 users, flat blob cost):", receipt.gasUsed.toString(), "gas");
            console.log("vs ALBA (128 proofs):", 253566 * 128, "gas");
            console.log("=====================================\n");
        });

        it("Should show flat gas scaling with blob DA", async function () {
            const testSizes = [8, 128, 512];
            console.log("\n=== Bitmap Scaling (EIP-4844 blob DA) ===");
            for (const size of testSizes) {
                const contract = await deployFreshContract();
                await doSetup(contract);
                const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`size_${size}`));
                const receipt = await submitMerkleRootWithBlob(contract, root, size, [], []);
                console.log(`Batch ${size}: ${receipt.gasUsed.toString()} gas (${Math.ceil(size / 256)} bitmap words)`);
            }
            console.log("=========================================\n");
        });
    });

    // ====== Backward Compatibility ======

    describe("Backward Compatibility", function () {
        it("Should work with traditional setup flow", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const state = await contract.state();
            expect(state.setupDone).to.equal(true);
        });

        it("Should work with dispute flow", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            const state = await contract.state();
            expect(state.disputeOpened).to.equal(true);
        });
    });

    // ====== Resolve Disputes ======

    describe("Resolve Disputes", function () {
        it("Should resolve valid dispute", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            await contract.resolveValidDispute(testdata.CT_P_withVsig_Unlocked);
            const state = await contract.state();
            expect(state.disputeClosedP).to.equal(true);
        });

        it("Should resolve invalid dispute", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            await contract.resolveInvalidDispute(testdata.revSecretP);
            const state = await contract.state();
            expect(state.disputeClosedV).to.equal(true);
        });

        it("Should revert valid dispute resolution after timeout", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await network.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]);
            await network.provider.send("evm_mine");

            await expect(
                contract.resolveValidDispute(testdata.CT_P_withVsig_Unlocked)
            ).to.be.revertedWith("Dispute resolution window closed");

            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Should revert invalid dispute resolution after timeout", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await network.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]);
            await network.provider.send("evm_mine");

            await expect(
                contract.resolveInvalidDispute(testdata.revSecretP)
            ).to.be.revertedWith("Dispute resolution window closed");

            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ====== Settle ======

    describe("Settle", function () {
        it("Should settle after invalid dispute resolved", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            await contract.resolveInvalidDispute(testdata.revSecretP);
            await contract.settle();
        });
    });

    // ====== Helper Functions ======

    describe("Helper Functions", function () {
        it("Should return 0 for unclaimed indices", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("helper_test"));
            await submitMerkleRootWithBlob(contract, root, 8, [], []);
            expect(await contract.getClaimedCount()).to.equal(0);
            expect(await contract.getBitmapWord(0)).to.equal(0);
            expect(await contract.isClaimed(5)).to.equal(false);
            expect(await contract.claimedCount()).to.equal(0);
        });
    });

    // ---------------------------------------------------------------------
    // Path 2b - Zero-claim timeout refund
    // ---------------------------------------------------------------------

    describe("Path 2b - zero-claim timeout settlement", function () {

        const CHALLENGE_WINDOW = 86400;      // 1 day
        const T_CLAIM          = 7 * 86400;  // 7 days

        it("settle() reverts before T_CLAIM expires (claim window still open)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("path2b_early"));
            await submitMerkleRootWithBlob(contract, root, 4, [], []);
            // Advance only past challenge window, NOT past T_CLAIM
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 60]);
            await network.provider.send("evm_mine");

            await expect(contract.settle()).to.be.revertedWith("Claim window still open");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("settle() succeeds after T_CLAIM expires with k=0, refunds deposits", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("path2b_ok"));
            await submitMerkleRootWithBlob(contract, root, 4, [], []);
            // Advance past challenge window + T_CLAIM
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + T_CLAIM + 60]);
            await network.provider.send("evm_mine");

            expect(await contract.claimedCount()).to.equal(0);
            await expect(contract.settle())
                .to.emit(contract, "stateEvent")
                .withArgs("Zero-claim timeout: deposits refunded", true);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 2b does not trigger if k > 0 (uses Path 2 instead)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            await deployer.sendTransaction({ to: contract.address, value: ethers.utils.parseEther("1") });

            const addrs2b = [deployer.address];
            const amounts2b = [ethers.utils.parseEther("0.1")];
            const { root, tree } = buildMerkleTree(contract.address, addrs2b, amounts2b);
            await submitMerkleRootWithBlob(contract, root, 1, addrs2b, amounts2b);
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 60]);
            await network.provider.send("evm_mine");

            const proof = getMerkleProof(tree, 0);
            await claimLeaf(contract, deployer.address, ethers.utils.parseEther("0.1"), proof, 0);
            expect(await contract.claimedCount()).to.equal(1);

            await network.provider.send("evm_increaseTime", [7 * 86400]); // advance past T_CLAIM for settle()
            await network.provider.send("evm_mine");
            await expect(contract.settle())
                .to.emit(contract, "stateEvent")
                .withArgs("Batch settled proportionally", true);
            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ---------------------------------------------------------------------
    // Path 3 - Freeze & Arbitration
    // ---------------------------------------------------------------------

    describe("Path 3 - Freeze & Arbitration", function () {
        const ARBITRATION_TIMEOUT = 7 * 24 * 60 * 60; // 7 days

        async function setupFrozenDispute() {
            const contract = await deployFreshContract();
            await doSetup(contract);
            // Open an unresolved dispute (no resolveValidDispute / resolveInvalidDispute called)
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            // Advance past dispute resolution window so dispute expires unresolved
            await network.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]);
            await network.provider.send("evm_mine");
            // settle() triggers Path 3 freeze
            await contract.settle();
            return contract;
        }

        it("settle() freezes D and emits DisputeFrozen on unresolved dispute", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await deployFreshContract();
            await doSetup(contract);
            await contract.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
            await network.provider.send("evm_increaseTime", [8 * 24 * 60 * 60]);
            await network.provider.send("evm_mine");

            await expect(contract.settle())
                .to.emit(contract, "stateEvent")
                .withArgs("Dispute unresolved: D frozen for arbitration", true);

            expect(await contract.frozen()).to.equal(true);
            expect(await contract.arbitrationDone()).to.equal(false);
            expect(await contract.frozenAmount()).to.be.gt(0);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorResolve(true) slashes prover - sends D to verifier", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            const frozenAmt = await contract.frozenAmount();
            const vBalBefore = await ethers.provider.getBalance(verifierAddress);

            await expect(contract.connect(deployer).arbitratorResolve(true))
                .to.emit(contract, "ArbitrationResolved");

            expect(await contract.arbitrationDone()).to.equal(true);
            expect(await contract.frozenAmount()).to.equal(0);

            const vBalAfter = await ethers.provider.getBalance(verifierAddress);
            expect(vBalAfter.sub(vBalBefore)).to.equal(frozenAmt);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorResolve(false) exonerates prover - sends D to prover", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            const frozenAmt = await contract.frozenAmount();
            const pBalBefore = await ethers.provider.getBalance(proverAddress);

            await expect(contract.connect(deployer).arbitratorResolve(false))
                .to.emit(contract, "ArbitrationResolved");

            expect(await contract.arbitrationDone()).to.equal(true);
            const pBalAfter = await ethers.provider.getBalance(proverAddress);
            expect(pBalAfter.sub(pBalBefore)).to.equal(frozenAmt);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorResolve reverts after ARBITRATION_TIMEOUT", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            await network.provider.send("evm_increaseTime", [ARBITRATION_TIMEOUT + 60]);
            await network.provider.send("evm_mine");

            await expect(contract.connect(deployer).arbitratorResolve(true))
                .to.be.revertedWith("Arbitration window expired");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorResolve reverts if caller is not arbitrator", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();
            const [, nonArb] = await ethers.getSigners();

            await expect(contract.connect(nonArb).arbitratorResolve(true))
                .to.be.revertedWith("Only arbitrator");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorFinalize() burns frozen D after timeout", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            await network.provider.send("evm_increaseTime", [ARBITRATION_TIMEOUT + 60]);
            await network.provider.send("evm_mine");

            await expect(contract.connect(deployer).arbitratorFinalize())
                .to.emit(contract, "stateEvent")
                .withArgs("Frozen D burned: arbitration timeout", true);

            expect(await contract.arbitrationDone()).to.equal(true);
            expect(await contract.frozenAmount()).to.equal(0);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("arbitratorFinalize() reverts before ARBITRATION_TIMEOUT", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            await expect(contract.connect(deployer).arbitratorFinalize())
                .to.be.revertedWith("Arbitration window still open");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("double arbitration reverts", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract = await setupFrozenDispute();

            await contract.connect(deployer).arbitratorResolve(true);
            await expect(contract.connect(deployer).arbitratorResolve(false))
                .to.be.revertedWith("Arbitration already done");
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("setArbitrator reverts after root submitted", async function () {
            const contract = await deployFreshContract();
            await doSetup(contract);
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("arb_test"));
            await submitMerkleRootWithBlob(contract, root, 1, [], []);
            // "Root already submitted" check fires before blob check
            await impersonateAndExecute(proverAddress, async (prover) => {
                await expect(contract.connect(prover).setArbitrator(deployer.address))
                    .to.be.revertedWith("Root already submitted");
            });
        });
    });
});

