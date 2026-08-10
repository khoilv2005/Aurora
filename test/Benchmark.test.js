const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const EthCrypto = require('eth-crypto');
const crypto = require('crypto');

/**
 * Comprehensive Gas Benchmark for Aurora (EIP-712 + EIP-4844)
 *
 * Leaf hashing: EIP-712 typed structured data (AuroraLeaf)
 * Data availability: EIP-4844 blob sidecar (blobhash opcode)
 */
describe("AuroraFull - Comprehensive Gas Benchmark", function() {
    let testdata;
    let proverAddress, verifierAddress;
    let identityP, identityV;
    let deployer;
    let auroraImpl, auroraFactory;

    const CHALLENGE_WINDOW = 86400; // 1 day
    const CHAIN_ID = 31337;         // hardhat default

    // -- EIP-712 constants ------------------------------------------------------
    const LEAF_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index)")
    );
    const DOMAIN_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )
    );

    // -- KZG singleton ----------------------------------------------------------
    let _kzg;
    async function getKZG() {
        if (!_kzg) {
            const { loadKZG } = require("kzg-wasm");
            _kzg = await loadKZG();
        }
        return _kzg;
    }

    // -- EIP-712 helpers --------------------------------------------------------
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

    // -- Merkle tree (EIP-712 leaves, double-hash) ------------------------------
    function hashPair(a, b) {
        return ethers.utils.keccak256(
            ethers.utils.solidityPack(["bytes32", "bytes32"], [a, b])
        );
    }

    function buildMerkleTree(contractAddr, addrs, amounts) {
        // Merkle leaf node = keccak256(eip712Digest)  - mirrors verifyMerkleProof
        let currentLevel = addrs.map((addr, i) => {
            const leaf = leafHash712(contractAddr, addr, amounts[i], i);
            return ethers.utils.keccak256(leaf);
        });
        const tree = [currentLevel.slice()];
        while (currentLevel.length > 1) {
            const next = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                next.push(
                    i + 1 < currentLevel.length
                        ? hashPair(currentLevel[i], currentLevel[i + 1])
                        : currentLevel[i]
                );
            }
            tree.push(next);
            currentLevel = next;
        }
        return { root: currentLevel[0], tree };
    }

    function getMerkleProof(tree, index) {
        const proof = [];
        let idx = index;
        for (let level = 0; level < tree.length - 1; level++) {
            const nodes = tree[level];
            const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
            if (sib < nodes.length) proof.push(nodes[sib]);
            idx = Math.floor(idx / 2);
        }
        return proof;
    }

    // -- EIP-4844 blob helpers --------------------------------------------------
    function buildBlobData(addrs, amounts) {
        const blob = new Uint8Array(131072); // 4096 fields × 32 bytes
        let offset = 0;
        for (let i = 0; i < addrs.length && offset + 96 <= 131072; i++) {
            blob.set(
                ethers.utils.arrayify(ethers.utils.hexZeroPad(addrs[i], 32)),
                offset
            );
            offset += 32;
            blob.set(
                ethers.utils.arrayify(
                    ethers.utils.hexZeroPad(
                        ethers.BigNumber.from(amounts[i]).toHexString(),
                        32
                    )
                ),
                offset
            );
            offset += 32;
            blob.set(
                ethers.utils.arrayify(
                    ethers.utils.hexZeroPad(
                        ethers.BigNumber.from(i).toHexString(),
                        32
                    )
                ),
                offset
            );
            offset += 32;
        }
        return blob;
    }

    /**
     * Send submitMerkleRoot as an EIP-4844 type-3 blob transaction.
     * Leaf DA data is encoded in the blob sidecar; blobhash(0) is stored on-chain.
     *
     * @param {string} proverPrivKey  hex private key (0x-prefixed) of the Prover
     * @param {Contract} contract     AuroraFull contract instance
     * @param {string} root           Merkle root bytes32
     * @param {number} batchSize      N
     * @param {string[]} addrs        leaf addresses (for blob packing)
     * @param {BigNumber[]} amounts   leaf amounts  (for blob packing)
     * @returns {TransactionReceipt}
     */
    async function submitMerkleRootWithBlob(
        proverPrivKey, contract, root, batchSize, addrs, amounts
    ) {
        const { BlobEIP4844Transaction } = require("@ethereumjs/tx");
        const { Common } = require("@ethereumjs/common");

        const kzg = await getKZG();

        // Build blob and KZG artifacts
        const blob = buildBlobData(addrs, amounts);
        const commitment = kzg.blobToKzgCommitment(blob);
        const kzgProof   = kzg.computeBlobKzgProof(blob, commitment);

        // Versioned hash: 0x01 || SHA256(commitment)[1:]
        const sha256 = crypto.createHash("sha256")
            .update(Buffer.from(commitment))
            .digest();
        sha256[0] = 0x01;
        const versionedHash = Uint8Array.from(sha256);

        // Signer from private key
        const wallet = new ethers.Wallet(proverPrivKey);
        await network.provider.send("hardhat_setBalance", [
            wallet.address, "0x100000000000000000000",
        ]);
        const nonce = await ethers.provider.getTransactionCount(wallet.address);
        const block = await ethers.provider.getBlock("latest");
        const baseFee = block.baseFeePerGas
            ? BigInt(block.baseFeePerGas.toString())
            : 1_000_000_000n;

        const calldata = contract.interface.encodeFunctionData(
            "submitMerkleRoot", [root, batchSize]
        );

        // KZG wrapper compatible with @ethereumjs/common customCrypto
        const kzgWrapper = {
            blobToKzgCommitment:    (b)          => kzg.blobToKzgCommitment(b),
            computeBlobKzgProof:    (b, c)       => kzg.computeBlobKzgProof(b, c),
            verifyKzgProof:         (c, z, y, p) => kzg.verifyKzgProof(c, z, y, p),
            verifyBlobKzgProofBatch:(bs, cs, ps) => kzg.verifyBlobKzgProofBatch(bs, cs, ps),
        };

        const common = Common.custom(
            { chainId: 31337, name: "hardhat", networkId: 31337 },
            { hardfork: "cancun", customCrypto: { kzg: kzgWrapper } }
        );

        const tx = BlobEIP4844Transaction.fromTxData(
            {
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
            },
            { common }
        );

        const privKeyBuf = Buffer.from(proverPrivKey.replace("0x", ""), "hex");
        const signedTx   = tx.sign(privKeyBuf);
        const rawHex     = "0x" + Buffer.from(signedTx.serializeNetworkWrapper()).toString("hex");

        const txHash = await ethers.provider.send("eth_sendRawTransaction", [rawHex]);
        await network.provider.send("evm_mine", []);
        return ethers.provider.getTransactionReceipt(txHash);
    }

    // -- Test infrastructure ----------------------------------------------------
    before(async () => {
        testdata = require("../data/jsonTestData.json");
        [deployer] = await ethers.getSigners();

        const entropyP = Buffer.from(
            'ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao',
            'utf-8'
        );
        identityP = EthCrypto.createIdentity(entropyP);
        proverAddress = EthCrypto.publicKey.toAddress(
            EthCrypto.publicKeyByPrivateKey(identityP.privateKey)
        );

        const entropyV = Buffer.from(
            'ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo',
            'utf-8'
        );
        identityV = EthCrypto.createIdentity(entropyV);
        verifierAddress = EthCrypto.publicKey.toAddress(
            EthCrypto.publicKeyByPrivateKey(identityV.privateKey)
        );

        const ImplFactory    = await ethers.getContractFactory("AuroraFull");
        auroraImpl           = await ImplFactory.deploy();
        await auroraImpl.deployed();

        const FactoryFactory = await ethers.getContractFactory("AuroraFactory");
        auroraFactory        = await FactoryFactory.deploy(auroraImpl.address);
        await auroraFactory.deployed();
    });

    async function impersonateAndExecute(address, executeFn) {
        await network.provider.send("hardhat_setBalance", [address, "0x100000000000000000000"]);
        await network.provider.request({ method: "hardhat_impersonateAccount", params: [address] });
        const signer = await ethers.getSigner(address);
        try { await executeFn(signer); }
        finally {
            await network.provider.request({
                method: "hardhat_stopImpersonatingAccount", params: [address],
            });
        }
    }

    async function doSetup(contract) {
        const digest     = testdata.setupMessageDigest;
        const signatureP = EthCrypto.sign(identityP.privateKey, digest);
        const signatureV = EthCrypto.sign(identityV.privateKey, digest);
        await contract.setup(
            testdata.fundingTxId, testdata.fundingTx_LockingScript,
            testdata.fundingTxIndex, testdata.sighash_all,
            testdata.pkProverUnprefixedUncompressed,
            testdata.pkVerifierUnprefixedUncompressed,
            testdata.timelock, testdata.RelTimelock,
            signatureP, signatureV
        );
        // Deposit Du as prover
        await impersonateAndExecute(proverAddress, async (proverSigner) => {
            await contract.connect(proverSigner).depositUserPool({
                value: ethers.utils.parseEther("2.5"),
            });
        });
        // Register deployer as batch participant
        await contract.connect(deployer).registerIntent();
    }

    async function deployFreshContract(ethAmount = "10") {
        const tx      = await auroraFactory.createBatch(proverAddress, verifierAddress);
        const receipt = await tx.wait();
        const event   = receipt.events.find(e => e.event === "BatchCreated");
        const contract = await ethers.getContractAt("AuroraFull", event.args.batch);
        await deployer.sendTransaction({
            to: contract.address, value: ethers.utils.parseEther(ethAmount),
        });
        return contract;
    }

    // ========================================================================
    // BENCHMARK 1: submitMerkleRoot - blob DA cost at various batch sizes
    // ========================================================================
    describe("BENCHMARK: submitMerkleRoot (blob DA, EIP-4844)", function () {
        const batchSizes = [1, 16, 64, 128, 256];

        for (const N of batchSizes) {
            it(`Batch size N=${N}`, async function () {
                this.timeout(120000);
                const contract = await deployFreshContract();
                await doSetup(contract);

                const addrs   = Array(N).fill(deployer.address);
                const amounts = Array(N).fill(ethers.utils.parseEther("0.01"));
                const root    = ethers.utils.keccak256(
                    ethers.utils.toUtf8Bytes(`bench_${N}`)
                );

                const receipt = await submitMerkleRootWithBlob(
                    identityP.privateKey, contract, root, N, addrs, amounts
                );
                const gasUsed = receipt.gasUsed.toNumber();
                console.log(
                    `submitMerkleRoot(N=${N}): ${gasUsed} gas | per-user: ${Math.round(gasUsed / N)} gas/user`
                );
            });
        }
    });

    // ========================================================================
    // BENCHMARK 2: claimWithMerkleProof (cold vs warm) at various tree depths
    // ========================================================================
    describe("BENCHMARK: claimWithMerkleProof (cold vs warm)", function () {
        const batchSizes = [4, 16, 64, 256];

        for (const N of batchSizes) {
            it(`Claim from tree of N=${N} leaves`, async function () {
                this.timeout(120000);
                const snapshotId = await network.provider.send("evm_snapshot");

                const contract = await deployFreshContract();
                await doSetup(contract);

                const addrs   = Array(N).fill(deployer.address);
                const amounts = Array(N).fill(ethers.utils.parseEther("0.001"));
                const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

                await submitMerkleRootWithBlob(
                    identityP.privateKey, contract, root, N, addrs, amounts
                );

                await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
                await network.provider.send("evm_mine");

                const proof0 = getMerkleProof(tree, 0);
                const tx0 = await contract.connect(deployer).claimWithMerkleProof(
                    deployer.address, ethers.utils.parseEther("0.001"), proof0, 0
                );
                const coldGas = (await tx0.wait()).gasUsed.toNumber();

                const proof1 = getMerkleProof(tree, 1);
                const tx1 = await contract.connect(deployer).claimWithMerkleProof(
                    deployer.address, ethers.utils.parseEther("0.001"), proof1, 1
                );
                const warmGas = (await tx1.wait()).gasUsed.toNumber();

                console.log(
                    `claim(N=${N}, depth=${proof0.length}): cold=${coldGas} | warm=${warmGas} | diff=${coldGas - warmGas}`
                );

                await network.provider.send("evm_revert", [snapshotId]);
            });
        }
    });

    // ========================================================================
    // BENCHMARK 3: challengeLeaf cost
    // ========================================================================
    describe("BENCHMARK: challengeLeaf", function () {
        it("Challenge an invalid leaf (addr=0)", async function () {
            this.timeout(120000);
            const contract = await deployFreshContract();
            await doSetup(contract);

            const addrs   = [ethers.constants.AddressZero, proverAddress];
            const amounts = [100, 200];
            const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

            await submitMerkleRootWithBlob(
                identityP.privateKey, contract, root, 2, addrs, amounts
            );

            const challengeProof = getMerkleProof(tree, 0);
            const tx = await contract.challengeLeaf(
                0, ethers.constants.AddressZero, 100, challengeProof
            );
            const receipt = await tx.wait();
            console.log(`challengeLeaf (addr=0): ${receipt.gasUsed.toNumber()} gas`);
        });

        it("Challenge an invalid leaf (amount=0)", async function () {
            this.timeout(120000);
            const contract = await deployFreshContract();
            await doSetup(contract);

            const addrs   = [proverAddress];
            const amounts = [0];
            const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

            await submitMerkleRootWithBlob(
                identityP.privateKey, contract, root, 1, addrs, amounts
            );

            const challengeProof = getMerkleProof(tree, 0);
            const tx = await contract.challengeLeaf(0, proverAddress, 0, challengeProof);
            const receipt = await tx.wait();
            console.log(`challengeLeaf (amount=0): ${receipt.gasUsed.toNumber()} gas`);
        });
    });

    // ========================================================================
    // BENCHMARK 4: settle (proportional, Path 2)
    // ========================================================================
    describe("BENCHMARK: settle (proportional)", function () {
        it("Settle after 50% claims (N=128)", async function () {
            this.timeout(120000);
            const snapshotId = await network.provider.send("evm_snapshot");

            const N       = 128;
            const contract = await deployFreshContract();
            await doSetup(contract);

            const addrs   = Array(N).fill(deployer.address);
            const amounts = Array(N).fill(ethers.utils.parseEther("0.01"));
            const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

            await submitMerkleRootWithBlob(
                identityP.privateKey, contract, root, N, addrs, amounts
            );

            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await network.provider.send("evm_mine");

            for (let i = 0; i < N / 2; i++) {
                await contract.connect(deployer).claimWithMerkleProof(
                    deployer.address,
                    ethers.utils.parseEther("0.01"),
                    getMerkleProof(tree, i),
                    i
                );
            }

            await network.provider.send("evm_increaseTime", [7 * 86400 + 1]);
            await network.provider.send("evm_mine");

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle (50% of N=128): ${receipt.gasUsed.toNumber()} gas`);

            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ========================================================================
    // BENCHMARK 5: settle() all paths
    // ========================================================================
    describe("BENCHMARK: settle() all paths", function () {

        it("Path 1 - Valid proof submitted (submitProof)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract   = await deployFreshContract();
            await doSetup(contract);

            await contract.submitProof(
                testdata.CT_P_withVsig_Unlocked,
                testdata.CT_V_withPsig_Unlocked
            );

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 1 (proof submitted): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 1b - Valid dispute resolved (resolveValidDispute)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract   = await deployFreshContract();
            await doSetup(contract);

            await contract.dispute(
                testdata.CT_P_withVsig_Locked,
                testdata.CT_V_withPsig_Unlocked
            );
            await contract.resolveValidDispute(testdata.CT_P_withVsig_Unlocked);

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 1b (valid dispute resolved): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 3 - Unresolved dispute (all to Prover)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract   = await deployFreshContract();
            await doSetup(contract);

            await contract.dispute(
                testdata.CT_P_withVsig_Locked,
                testdata.CT_V_withPsig_Unlocked
            );

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 3 (unresolved dispute): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 4 - Revocation revealed (all to Verifier)", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");
            const contract   = await deployFreshContract();
            await doSetup(contract);

            await contract.dispute(
                testdata.CT_P_withVsig_Locked,
                testdata.CT_V_withPsig_Unlocked
            );
            await contract.resolveInvalidDispute(testdata.revSecretP);

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 4 (revocation): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 5 - No setup, refund deposits", async function () {
            const snapshotId = await network.provider.send("evm_snapshot");

            const tx0    = await auroraFactory.createBatch(proverAddress, verifierAddress);
            const rcpt0  = await tx0.wait();
            const ev0    = rcpt0.events.find(e => e.event === "BatchCreated");
            const contract = await ethers.getContractAt("AuroraFull", ev0.args.batch);

            await impersonateAndExecute(proverAddress, async (prover) => {
                await prover.sendTransaction({
                    to: contract.address, value: ethers.utils.parseEther("5"),
                });
            });
            await impersonateAndExecute(verifierAddress, async (verif) => {
                await verif.sendTransaction({
                    to: contract.address, value: ethers.utils.parseEther("5"),
                });
            });

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 5 (refund, no setup): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });

        it("Path 2b - Zero-claim timeout refund", async function () {
            this.timeout(120000);
            const T_CLAIM    = 7 * 86400;
            const snapshotId = await network.provider.send("evm_snapshot");

            const contract = await deployFreshContract();
            await doSetup(contract);

            const root    = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("bench_path2b"));
            const addrs   = [ethers.constants.AddressZero, ethers.constants.AddressZero];
            const amounts = [0, 0];

            await submitMerkleRootWithBlob(
                identityP.privateKey, contract, root, 2, addrs, amounts
            );

            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + T_CLAIM + 60]);
            await network.provider.send("evm_mine");

            const tx      = await contract.settle();
            const receipt = await tx.wait();
            console.log(`settle Path 2b (zero-claim timeout): ${receipt.gasUsed.toNumber()} gas`);
            await network.provider.send("evm_revert", [snapshotId]);
        });
    });

    // ========================================================================
    // BENCHMARK 6: Amortized cost summary
    // ========================================================================
    describe("BENCHMARK: Amortized cost summary", function () {

        const batchSizes = [1, 16, 64, 128, 256];

        it("Generate amortized cost table", async function () {
            this.timeout(600000);

            console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
            console.log("║    AURORA GAS BENCHMARK (EIP-712 leaves + EIP-4844 blob DA)         ║");
            console.log("╠═══════╦═════════════╦══════════╦══════════╦═══════════╦══════════════╣");
            console.log("║   N   ║  Root Gas   ║ Cold Gas ║ Warm Gas ║ Amort/Usr ║ vs Alba(%)   ║");
            console.log("╠═══════╬═════════════╬══════════╬══════════╬═══════════╬══════════════╣");

            for (const N of batchSizes) {
                const snapshotId = await network.provider.send("evm_snapshot");
                const contract   = await deployFreshContract();
                await doSetup(contract);

                const addrs   = Array(N).fill(deployer.address);
                const amounts = Array(N).fill(ethers.utils.parseEther("0.001"));
                const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

                const rootReceipt = await submitMerkleRootWithBlob(
                    identityP.privateKey, contract, root, N, addrs, amounts
                );
                const rootGas = rootReceipt.gasUsed.toNumber();

                await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
                await network.provider.send("evm_mine");

                let coldGas = 0, warmGas = 0;
                if (N >= 2) {
                    const tx0 = await contract.connect(deployer).claimWithMerkleProof(
                        deployer.address,
                        ethers.utils.parseEther("0.001"),
                        getMerkleProof(tree, 0), 0
                    );
                    coldGas = (await tx0.wait()).gasUsed.toNumber();

                    const tx1 = await contract.connect(deployer).claimWithMerkleProof(
                        deployer.address,
                        ethers.utils.parseEther("0.001"),
                        getMerkleProof(tree, 1), 1
                    );
                    warmGas = (await tx1.wait()).gasUsed.toNumber();
                } else {
                    const tx0 = await contract.connect(deployer).claimWithMerkleProof(
                        deployer.address,
                        ethers.utils.parseEther("0.001"),
                        getMerkleProof(tree, 0), 0
                    );
                    coldGas = warmGas = (await tx0.wait()).gasUsed.toNumber();
                }

                const amortized  = Math.round(rootGas / N + warmGas);
                const albaPerUser = 253566;
                const savings    = ((1 - amortized / albaPerUser) * 100).toFixed(1);

                console.log(
                    `║ ${String(N).padStart(5)} ║ ${String(rootGas).padStart(11)} ║` +
                    ` ${String(coldGas).padStart(8)} ║ ${String(warmGas).padStart(8)} ║` +
                    ` ${String(amortized).padStart(9)} ║ ${String(savings + '%').padStart(12)} ║`
                );

                await network.provider.send("evm_revert", [snapshotId]);
            }

            console.log("╚═══════╩═════════════╩══════════╩══════════╩═══════════╩══════════════╝");
            console.log("Alba baseline: 253,566 gas/user");
        });
    });

    // ========================================================================
    // BENCHMARK 7: Sparse Claim Analysis
    //   Fixed N=100; vary f ∈ {10%,25%,50%,75%,100%} of users who claim.
    //   Measures C_eff(N,f) = G_sub/(f·N) + G_claim_warm
    //   Validates that Aurora saves gas vs Alba even at low participation.
    // ========================================================================
    describe("BENCHMARK: Sparse Claim Analysis (N=128, Path 2 settle)", function () {
        // N=128 (nearest power-of-2 to baseline N=100) avoids Merkle-tree padding
        // issues for non-power-of-2 leaf counts; depth K=7 is identical to N=100.
        const N              = 128;
        const T_CLAIM        = 7 * 86400;
        const claimFractions = [0.10, 0.25, 0.50, 0.75, 1.00];
        const ALBA_BASELINE  = 253566;

        it("Sparse claim gas table (N=128) - f = 10%/25%/50%/75%/100%", async function () {
            this.timeout(1200000);

            const results = [];

            for (const f of claimFractions) {
                const snapshotId = await network.provider.send("evm_snapshot");

                const contract = await deployFreshContract("15");
                await doSetup(contract);

                // Build N-leaf Merkle tree (all leaves owned by deployer for gas purity)
                const addrs   = Array(N).fill(deployer.address);
                const amounts = Array(N).fill(ethers.utils.parseEther("0.05"));
                const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

                // -- submitMerkleRoot (blob DA) ------------------------------
                const subReceipt = await submitMerkleRootWithBlob(
                    identityP.privateKey, contract, root, N, addrs, amounts
                );
                const gSub = subReceipt.gasUsed.toNumber();

                // -- Advance past challenge window -> claim phase -------------
                await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
                await network.provider.send("evm_mine");

                // -- Execute f·N claims --------------------------------------
                const numClaims = Math.max(1, Math.round(f * N));
                let gClaimCold = 0;
                let gClaimWarm = 0;

                for (let i = 0; i < numClaims; i++) {
                    const tx = await contract.connect(deployer).claimWithMerkleProof(
                        deployer.address,
                        ethers.utils.parseEther("0.05"),
                        getMerkleProof(tree, i),
                        i
                    );
                    const g = (await tx.wait()).gasUsed.toNumber();
                    if (i === 0) gClaimCold = g;
                    if (i === 1) gClaimWarm = g;
                }
                // Edge: single claim has no "warm" measurement
                if (numClaims === 1) gClaimWarm = gClaimCold;

                // -- Advance past T_CLAIM -> settle (Path 2 proportional) ----
                await network.provider.send("evm_increaseTime", [T_CLAIM + 60]);
                await network.provider.send("evm_mine");

                const settleTx = await contract.settle();
                const gSettle  = (await settleTx.wait()).gasUsed.toNumber();

                // -- Metrics -------------------------------------------------
                // C_eff: effective per-claiming-user gas (sub amortized over claimants)
                const cEff    = Math.round(gSub / numClaims + gClaimWarm);
                const savings = ((1 - cEff / ALBA_BASELINE) * 100).toFixed(1);

                // Total protocol gas: compare Aurora batch vs equivalent Alba
                const auroraTotal = gSub + numClaims * gClaimWarm + gSettle;
                const albaTotal   = numClaims * ALBA_BASELINE;
                const totalSavings = ((1 - auroraTotal / albaTotal) * 100).toFixed(1);

                results.push({ f, numClaims, gSub, gClaimCold, gClaimWarm, gSettle, cEff, savings, auroraTotal, albaTotal, totalSavings });

                await network.provider.send("evm_revert", [snapshotId]);
            }

            // -- Print per-claimant cost table -------------------------------
            console.log("\n╔══════════════════════════════════════════════════════════════════════════════════╗");
            console.log("║  SPARSE CLAIM ANALYSIS - Per-claimant effective gas (N=100, Path 2 settle)     ║");
            console.log("╠══════╦══════════╦══════════╦══════════╦═══════════╦═════════════╦═════════════╣");
            console.log("║   f  ║ #Claims  ║  G_sub   ║ G_claim  ║  G_settle ║ C_eff/claim ║  vs Alba    ║");
            console.log("╠══════╬══════════╬══════════╬══════════╬═══════════╬═════════════╬═════════════╣");
            for (const r of results) {
                console.log(
                    `║ ${String((r.f * 100).toFixed(0) + '%').padStart(4)} ║` +
                    ` ${String(r.numClaims).padStart(8)} ║` +
                    ` ${String(r.gSub).padStart(8)} ║` +
                    ` ${String(r.gClaimWarm).padStart(8)} ║` +
                    ` ${String(r.gSettle).padStart(9)} ║` +
                    ` ${String(r.cEff).padStart(11)} ║` +
                    ` ${String(r.savings + '%').padStart(11)} ║`
                );
            }
            console.log("╚══════╩══════════╩══════════╩══════════╩═══════════╩═════════════╩═════════════╝");

            // -- Print total protocol gas comparison -------------------------
            console.log("\n╔══════════════════════════════════════════════════════════════════╗");
            console.log("║  TOTAL PROTOCOL GAS: Aurora batch vs equivalent Alba txns       ║");
            console.log("╠══════╦══════════╦═════════════╦═════════════╦══════════════════╣");
            console.log("║   f  ║ #Claims  ║ Aurora total ║  Alba total  ║ Protocol savings ║");
            console.log("╠══════╬══════════╬═════════════╬═════════════╬══════════════════╣");
            for (const r of results) {
                console.log(
                    `║ ${String((r.f * 100).toFixed(0) + '%').padStart(4)} ║` +
                    ` ${String(r.numClaims).padStart(8)} ║` +
                    ` ${String(r.auroraTotal).padStart(11)} ║` +
                    ` ${String(r.albaTotal).padStart(11)} ║` +
                    ` ${String(r.totalSavings + '%').padStart(16)} ║`
                );
            }
            console.log("╚══════╩══════════╩═════════════╩═════════════╩══════════════════╝");
            console.log("Break-even: Aurora total < Alba total for f > G_sub / (N*(Alba - G_claim))");
            console.log(`  = ${Math.round(results[0].gSub)} / (${N} * (${ALBA_BASELINE} - ${results[0].gClaimWarm})) ≈ ${(results[0].gSub / (N * (ALBA_BASELINE - results[0].gClaimWarm)) * 100).toFixed(1)}%`);
        });
    });

    // ========================================================================
    // BENCHMARK 8: Sparse Claims - vary both N and f
    //   Shows how batch size amplifies the sparse-claim advantage.
    // ========================================================================
    describe("BENCHMARK: Sparse Claims - vary N at fixed f=50%", function () {
        const claimFraction  = 0.50;
        const batchSizes     = [16, 64, 128, 256];
        const T_CLAIM        = 7 * 86400;
        const ALBA_BASELINE  = 253566;

        it("Sparse (f=50%) amortized cost at N=10/50/100/250", async function () {
            this.timeout(1200000);

            console.log("\n╔════════════════════════════════════════════════════════════════════╗");
            console.log("║  SPARSE (f=50%) - C_eff vs batch size N                          ║");
            console.log("╠═══════╦══════════╦══════════╦══════════╦═════════════╦════════════╣");
            console.log("║   N   ║ #Claims  ║  G_sub   ║ G_claim  ║ C_eff/claim ║  vs Alba   ║");
            console.log("╠═══════╬══════════╬══════════╬══════════╬═════════════╬════════════╣");

            for (const N of batchSizes) {
                const snapshotId = await network.provider.send("evm_snapshot");

                const contract = await deployFreshContract("15");
                await doSetup(contract);

                const addrs   = Array(N).fill(deployer.address);
                const amounts = Array(N).fill(ethers.utils.parseEther("0.05"));
                const { root, tree } = buildMerkleTree(contract.address, addrs, amounts);

                const subReceipt = await submitMerkleRootWithBlob(
                    identityP.privateKey, contract, root, N, addrs, amounts
                );
                const gSub = subReceipt.gasUsed.toNumber();

                await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
                await network.provider.send("evm_mine");

                const numClaims  = Math.max(1, Math.round(claimFraction * N));
                let gClaimWarm   = 0;

                for (let i = 0; i < numClaims; i++) {
                    const tx = await contract.connect(deployer).claimWithMerkleProof(
                        deployer.address,
                        ethers.utils.parseEther("0.05"),
                        getMerkleProof(tree, i),
                        i
                    );
                    const g = (await tx.wait()).gasUsed.toNumber();
                    if (i === 1) gClaimWarm = g;
                    else if (i === 0 && numClaims === 1) gClaimWarm = g;
                }

                await network.provider.send("evm_increaseTime", [T_CLAIM + 60]);
                await network.provider.send("evm_mine");
                await contract.settle();

                const cEff    = Math.round(gSub / numClaims + gClaimWarm);
                const savings = ((1 - cEff / ALBA_BASELINE) * 100).toFixed(1);

                console.log(
                    `║ ${String(N).padStart(5)} ║` +
                    ` ${String(numClaims).padStart(8)} ║` +
                    ` ${String(gSub).padStart(8)} ║` +
                    ` ${String(gClaimWarm).padStart(8)} ║` +
                    ` ${String(cEff).padStart(11)} ║` +
                    ` ${String(savings + '%').padStart(10)} ║`
                );

                await network.provider.send("evm_revert", [snapshotId]);
            }

            console.log("╚═══════╩══════════╩══════════╩══════════╩═════════════╩════════════╝");
            console.log("C_eff(N,f=50%) = G_sub/(0.5·N) + G_claim_warm");
        });
    });
});

