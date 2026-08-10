/**
 * AuroraFactory.test.js
 *
 * Tests for AuroraFull (initializable) and AuroraFactory (EIP-1167 clone deployer).
 *
 * Covers:
 *   1. AuroraFull standalone - initialize() works, cannot re-initialize
 *   2. AuroraFactory - createBatch() deploys a clone, clone is functional
 *   3. Clone isolation - two clones have independent state
 *   4. Clone gas - deployment cost ~45,000 gas (vs. ~5.8M for full deploy)
 *   5. Clone protocol - submitMerkleRoot + claimWithMerkleProof on a factory clone
 */
const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const EthCrypto = require('eth-crypto');
const crypto = require("crypto");

describe("AuroraFactory + AuroraFull (EIP-1167 clone pattern)", function () {

    let testdata;
    let proverAddress, verifierAddress;
    let identityP, identityV;
    let deployer;
    let implV2;       // AuroraFull implementation contract
    let factory;      // AuroraFactory

    const CHALLENGE_WINDOW = 86400; // 1 day

    before(async () => {
        testdata = require("../data/jsonTestData.json");
        [deployer] = await ethers.getSigners();

        const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
        identityP = EthCrypto.createIdentity(entropyP);
        proverAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityP.privateKey));

        const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
        identityV = EthCrypto.createIdentity(entropyV);
        verifierAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityV.privateKey));

        // Deploy implementation (locked - _initialized = true in constructor)
        const ImplFactory = await ethers.getContractFactory("AuroraFull");
        implV2 = await ImplFactory.deploy();
        await implV2.deployed();

        // Deploy factory pointing at implementation
        const FactoryFactory = await ethers.getContractFactory("AuroraFactory");
        factory = await FactoryFactory.deploy(implV2.address);
        await factory.deployed();
    });

    // ---------------------------------------------------------------
    // Helpers (same as Aurora.test.js)
    // ---------------------------------------------------------------

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
        // H2: deposit Du (user protection pool)
        await impersonateAndExecute(proverAddress, async (proverSigner) => {
            await contract.connect(proverSigner).depositUserPool({
                value: ethers.utils.parseEther("1")
            });
        });
        // Fix A: register deployer as the leaf beneficiary (deployer != prover != verifier)
        await contract.connect(deployer).registerIntent();
    }

    async function claimLeaf(contract, addr, amount, proof, index) {
        // addr must be deployer (registered, non-prover/verifier)
        await contract.connect(deployer).claimWithMerkleProof(addr, amount, proof, index);
    }

    async function deployClone() {
        const tx = await factory.createBatch(proverAddress, verifierAddress);
        const receipt = await tx.wait();
        const event = receipt.events.find(e => e.event === "BatchCreated");
        const cloneAddr = event.args.batch;
        const clone = await ethers.getContractAt("AuroraFull", cloneAddr);
        // Fund clone with 1 ETH so settle() can pay out
        await deployer.sendTransaction({ to: cloneAddr, value: ethers.utils.parseEther("1") });
        return { clone, cloneAddr, receipt };
    }

    function hashLeaf(data) { return ethers.utils.keccak256(data); }
    function hashPair(a, b) { return ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32", "bytes32"], [a, b])); }

    function buildLeafData(contractAddress, addr, amount, index) {
        return ethers.utils.defaultAbiCoder.encode(
            ["address", "address", "uint256", "uint256"],
            [contractAddress, addr, amount, index]
        );
    }

    function buildMerkleTree(rawDataArray) {
        const rawLeafHashes = rawDataArray.map(data => hashLeaf(data));
        let currentLevel = rawLeafHashes.map(h =>
            ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32"], [h]))
        );
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
        return { root: currentLevel[0], rawLeafHashes, tree };
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

    // -- EIP-712 leaf hash helpers (mirrors AuroraFull._leafHash) --------------
    const LEAF_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index)")
    );
    const DOMAIN_TYPEHASH = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    );

    function getDomainSeparator(contractAddr) {
        return ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
            ["bytes32","bytes32","bytes32","uint256","address"],
            [DOMAIN_TYPEHASH,
             ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
             ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")),
             31337,
             contractAddr]
        ));
    }

    function leafHash712(contractAddr, addr, amount, index) {
        const ds = getDomainSeparator(contractAddr);
        const structHash = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ["bytes32","address","uint256","uint256"],
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

    function buildMerkleTree712(contractAddr, addrs, amounts) {
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

    // -- EIP-4844 blob tx helper (mirrors Aurora.test.js exactly) ------------
    let _kzg;
    async function getKZG() {
        if (!_kzg) { const { loadKZG } = require("kzg-wasm"); _kzg = await loadKZG(); }
        return _kzg;
    }

    async function submitMerkleRootWithBlob(privKey, contract, root, batchSize) {
        const { BlobEIP4844Transaction } = require("@ethereumjs/tx");
        const { Common } = require("@ethereumjs/common");
        const kzg = await getKZG();
        const blob = new Uint8Array(131072);
        const commitment = kzg.blobToKzgCommitment(blob);
        const kzgProof   = kzg.computeBlobKzgProof(blob, commitment);
        const sha256h = crypto.createHash("sha256").update(Buffer.from(commitment)).digest();
        sha256h[0] = 0x01;
        const versionedHash = Uint8Array.from(sha256h);
        const wallet = new ethers.Wallet(privKey);
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
        const privKeyBuf = Buffer.from(privKey.replace("0x", ""), "hex");
        const signedTx   = tx.sign(privKeyBuf);
        const rawHex     = "0x" + Buffer.from(signedTx.serializeNetworkWrapper()).toString("hex");
        const txHash = await ethers.provider.send("eth_sendRawTransaction", [rawHex]);
        await network.provider.send("evm_mine", []);
        return ethers.provider.getTransactionReceipt(txHash);
    }

    // ---------------------------------------------------------------
    // §1 - AuroraFull standalone initializer
    // ---------------------------------------------------------------

    describe("AuroraFull - initialize()", function () {

        it("Implementation contract is locked (cannot be initialized)", async function () {
            await expect(
                implV2.initialize(proverAddress, verifierAddress)
            ).to.be.revertedWith("Already initialized");
        });

        it("Fresh clone initializes correctly", async function () {
            const { clone } = await deployClone();
            // prover and verifier are private - verify indirectly via a guarded call
            // submitMerkleRoot requires caller == prover, so if wrong address is rejected it means init worked
            const root = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("init-test"));
            await doSetup(clone);
            await impersonateAndExecute(proverAddress, async (prover) => {
                // Should NOT revert "Only prover" - prover was set correctly
                const da = { addrs: [ethers.constants.AddressZero], amounts: [0] };
                await expect(
                    clone.connect(prover).submitMerkleRoot(root, 1, da.addrs, da.amounts)
                ).to.not.be.revertedWith("Only prover");
            });
        });

        it("Clone cannot be re-initialized after first call", async function () {
            const { clone } = await deployClone();
            await expect(
                clone.initialize(proverAddress, verifierAddress)
            ).to.be.revertedWith("Already initialized");
        });

    });

    // ---------------------------------------------------------------
    // §2 - AuroraFactory deployment
    // ---------------------------------------------------------------

    describe("AuroraFactory - createBatch()", function () {

        it("Factory stores correct implementation address", async function () {
            expect(await factory.implementation()).to.equal(implV2.address);
        });

        it("createBatch() emits BatchCreated event", async function () {
            const tx = await factory.createBatch(proverAddress, verifierAddress);
            const receipt = await tx.wait();
            const event = receipt.events.find(e => e.event === "BatchCreated");
            expect(event).to.not.be.undefined;
            expect(event.args.index).to.be.gte(0);
            expect(event.args.batch).to.match(/^0x[0-9a-fA-F]{40}$/);
        });

        it("batchCount() increments on each createBatch()", async function () {
            const before = (await factory.batchCount()).toNumber();
            await factory.createBatch(proverAddress, verifierAddress);
            await factory.createBatch(proverAddress, verifierAddress);
            const after = (await factory.batchCount()).toNumber();
            expect(after).to.equal(before + 2);
        });

        it("Clone address differs from implementation", async function () {
            const { cloneAddr } = await deployClone();
            expect(cloneAddr).to.not.equal(implV2.address);
        });

        it("Clone gas overhead is << 5.8M (full deploy) - target < 300,000 gas", async function () {
            // createBatch() = clone deploy (~45k) + initialize() call (2x SSTORE ~40k each) + event
            // Total ~163k - well below 5,863,519 gas for full Aurora deploy
            const tx = await factory.createBatch(proverAddress, verifierAddress);
            const receipt = await tx.wait();
            console.log(`      createBatch() gas used: ${receipt.gasUsed.toString()}`);
            expect(receipt.gasUsed.toNumber()).to.be.lt(300_000);
        });

    });

    // ---------------------------------------------------------------
    // §3 - Clone isolation (two clones have independent state)
    // ---------------------------------------------------------------

    describe("Clone isolation - independent state per instance", function () {

        it("Two clones have distinct addresses", async function () {
            const { cloneAddr: addr1 } = await deployClone();
            const { cloneAddr: addr2 } = await deployClone();
            expect(addr1).to.not.equal(addr2);
        });

        it("submitMerkleRoot on clone A does not affect clone B", async function () {
            const { clone: cloneA, cloneAddr: addrA } = await deployClone();
            const { clone: cloneB } = await deployClone();

            await doSetup(cloneA);
            await doSetup(cloneB);

            const leafDataA = buildLeafData(addrA, proverAddress, 100, 0);
            const { root: rootA } = buildMerkleTree([leafDataA]);

            await submitMerkleRootWithBlob(identityP.privateKey, cloneA, rootA, 1);

            // Clone A has the root, clone B does not
            expect(await cloneA.currentMerkleRoot()).to.equal(rootA);
            expect(await cloneB.currentMerkleRoot()).to.equal(ethers.constants.HashZero);
        });

    });

    // ---------------------------------------------------------------
    // §4 - Full protocol flow on a factory clone
    // ---------------------------------------------------------------

    describe("Clone protocol flow - setup -> submit -> claim -> settle", function () {

        let clone, cloneAddr;

        before(async () => {
            const result = await deployClone();
            clone = result.clone;
            cloneAddr = result.cloneAddr;
            await doSetup(clone);
        });

        it("submitMerkleRoot works on a clone", async function () {
            const N = 4;
            const addrs   = Array(N).fill(deployer.address);
            const amounts = Array.from({length: N}, (_, i) => 100 + i);
            const { root } = buildMerkleTree712(cloneAddr, addrs, amounts);

            const receipt = await submitMerkleRootWithBlob(identityP.privateKey, clone, root, N);
            expect(receipt.status).to.equal(1);
            expect(await clone.currentMerkleRoot()).to.equal(root);
            expect(await clone.batchSize()).to.equal(N);
        });

        it("claimWithMerkleProof works on a clone (index 0)", async function () {
            const N = 4;
            const addrs   = Array(N).fill(deployer.address);
            const amounts = Array.from({length: N}, (_, i) => 100 + i);
            const { root, tree } = buildMerkleTree712(cloneAddr, addrs, amounts);
            const proof = getMerkleProof(tree, 0);

            // Advance past challenge window so claim is allowed
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 60]);
            await network.provider.send("evm_mine");

            const alreadyClaimed = await clone.isClaimed(0);
            if (!alreadyClaimed) {
                await expect(
                    clone.connect(deployer).claimWithMerkleProof(deployer.address, 100, proof, 0)
                ).to.emit(clone, "leafClaimed");
            }

            expect(await clone.isClaimed(0)).to.equal(true);
        });

        it("Challenge window expires after 1 day and settle is callable", async function () {
            // Advance time past challenge window
            const snapshotId = await network.provider.send("evm_snapshot");
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 60]);
            await network.provider.send("evm_mine");

            await impersonateAndExecute(proverAddress, async (prover) => {
                // settle should not revert with "Challenge window still open"
                await expect(
                    clone.connect(prover).settle()
                ).to.not.be.revertedWith("Challenge window still open");
            });

            await network.provider.send("evm_revert", [snapshotId]);
        });

    });

    // ---------------------------------------------------------------
    // §5 - Replay resistance: same leaf rejected on different clone
    // ---------------------------------------------------------------

    describe("Replay resistance - leaf from clone A rejected on clone B", function () {

        it("Merkle proof built for clone A does not verify on clone B", async function () {
            const { clone: cloneA, cloneAddr: addrA } = await deployClone();
            const { clone: cloneB, cloneAddr: addrB } = await deployClone();

            await doSetup(cloneA);
            await doSetup(cloneB);

            // Build EIP-712 tree for clone A - leaf encoded with addrA as contract address
            const { root: rootA, tree: treeA } = buildMerkleTree712(addrA, [deployer.address], [500]);
            const proof = getMerkleProof(treeA, 0);

            // Submit rootA on clone A; submit same rootA on clone B
            // (same root bytes, but clone B has different address -> different domain separator)
            await submitMerkleRootWithBlob(identityP.privateKey, cloneA, rootA, 1);
            await submitMerkleRootWithBlob(identityP.privateKey, cloneB, rootA, 1);

            // Advance past challenge window
            await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 60]);
            await network.provider.send("evm_mine");

            // Claim on clone A succeeds - leaf encoded with addrA
            await expect(
                cloneA.connect(deployer).claimWithMerkleProof(deployer.address, 500, proof, 0)
            ).to.emit(cloneA, "leafClaimed");

            // Same proof on clone B fails - leaf was encoded with addrA, not addrB
            await expect(
                cloneB.connect(deployer).claimWithMerkleProof(deployer.address, 500, proof, 0)
            ).to.be.revertedWith("Invalid Merkle proof");
        });

    });

});

