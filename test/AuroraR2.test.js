const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const EthCrypto = require("eth-crypto");
const crypto = require("crypto");

describe("Aurora R2 - registration-bound batch invariants", function () {
  const CHALLENGE_WINDOW = 24 * 60 * 60;
  const LEAF_TYPEHASH = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index,bytes32 obligationCommitment)")
  );
  const DOMAIN_TYPEHASH = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
  );

  let deployer, alice, bob, carol;
  let identityP, identityV, proverAddress, verifierAddress, testdata;
  let implementation, factory;

  before(async function () {
    [deployer, alice, bob, carol] = await ethers.getSigners();
    testdata = require("../data/jsonTestData.json");
    identityP = EthCrypto.createIdentity(Buffer.from("aurora-r2-prover-entropy".repeat(8)));
    identityV = EthCrypto.createIdentity(Buffer.from("aurora-r2-verifier-entropy".repeat(8)));
    proverAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityP.privateKey));
    verifierAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityV.privateKey));

    const Aurora = await ethers.getContractFactory("AuroraFull");
    implementation = await Aurora.deploy();
    await implementation.deployed();
    const Factory = await ethers.getContractFactory("AuroraFactory");
    factory = await Factory.deploy(implementation.address);
    await factory.deployed();
  });

  async function asProver(fn) {
    await network.provider.send("hardhat_setBalance", [proverAddress, "0x10000000000000000000"]);
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [proverAddress] });
    try {
      return await fn(await ethers.getSigner(proverAddress));
    } finally {
      await network.provider.request({ method: "hardhat_stopImpersonatingAccount", params: [proverAddress] });
    }
  }

  function obligationCommitment(index) {
    return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`aurora-r2-obligation-${index}`));
  }

  function leafHash(contractAddress, addr, amount, index, commitment) {
    const domain = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        DOMAIN_TYPEHASH,
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")),
        31337,
        contractAddress,
      ]
    ));
    const structHash = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "address", "uint256", "uint256", "bytes32"],
      [LEAF_TYPEHASH, addr, amount, index, commitment]
    ));
    return ethers.utils.keccak256(ethers.utils.concat([
      ethers.utils.arrayify("0x1901"), ethers.utils.arrayify(domain), ethers.utils.arrayify(structHash),
    ]));
  }

  function hashPair(left, right) {
    return ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32", "bytes32"], [left, right]));
  }

  function dummyLeafNode(contractAddress) {
    return ethers.utils.keccak256(ethers.utils.solidityPack(["string", "address"], ["AURORA_DUMMY", contractAddress]));
  }

  function buildRegistrationTree(contractAddress, registrations) {
    let padded = 1;
    while (padded < registrations.length) padded *= 2;
    let nodes = Array.from({ length: padded }, (_, index) => {
      if (!registrations[index]) return dummyLeafNode(contractAddress);
      const entry = registrations[index];
      return ethers.utils.keccak256(leafHash(contractAddress, entry.addr, entry.amount, index, entry.commitment));
    });
    const tree = [nodes];
    while (nodes.length > 1) {
      const next = [];
      for (let i = 0; i < nodes.length; i += 2) next.push(hashPair(nodes[i], nodes[i + 1]));
      tree.push(next);
      nodes = next;
    }
    return { root: nodes[0], padded, tree };
  }

  function proofFor(tree, index) {
    const proof = [];
    let idx = index;
    for (let level = 0; level < tree.length - 1; level++) {
      proof.push(tree[level][idx % 2 === 0 ? idx + 1 : idx - 1]);
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  async function registerAs(address, batch, amount, commitment) {
    await network.provider.send("hardhat_setBalance", [address, "0x1000000000000000000"]);
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [address] });
    try {
      await batch.connect(await ethers.getSigner(address)).registerIntent(amount, commitment);
    } finally {
      await network.provider.request({ method: "hardhat_stopImpersonatingAccount", params: [address] });
    }
  }

  async function deployReadyBatch(factoryToUse = factory) {
    const create = await factoryToUse.createBatch(proverAddress, verifierAddress);
    const created = await create.wait();
    const batchAddress = created.events.find((event) => event.event === "BatchCreated").args.batch;
    const batch = await ethers.getContractAt("AuroraFull", batchAddress);
    await deployer.sendTransaction({ to: batch.address, value: ethers.utils.parseEther("2") });
    const sigP = EthCrypto.sign(identityP.privateKey, testdata.setupMessageDigest);
    const sigV = EthCrypto.sign(identityV.privateKey, testdata.setupMessageDigest);
    await batch.setup(
      testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex,
      testdata.sighash_all, testdata.pkProverUnprefixedUncompressed,
      testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, sigP, sigV
    );
    await asProver(async (prover) => {
      await batch.connect(prover).depositUserPool({ value: ethers.utils.parseEther("1") });
    });
    return batch;
  }

  let kzg;
  async function submitWithBlob(batch, root, padded) {
    if (!kzg) kzg = await require("kzg-wasm").loadKZG();
    const { BlobEIP4844Transaction } = require("@ethereumjs/tx");
    const { Common } = require("@ethereumjs/common");
    const blob = new Uint8Array(131072);
    const commitment = kzg.blobToKzgCommitment(blob);
    const proof = kzg.computeBlobKzgProof(blob, commitment);
    const versionedHash = crypto.createHash("sha256").update(Buffer.from(commitment)).digest();
    versionedHash[0] = 0x01;
    const wallet = new ethers.Wallet(identityP.privateKey);
    await network.provider.send("hardhat_setBalance", [wallet.address, "0x100000000000000000000"]);
    const latest = await ethers.provider.getBlock("latest");
    const baseFee = latest.baseFeePerGas ? BigInt(latest.baseFeePerGas.toString()) : 1_000_000_000n;
    const wrapper = {
      blobToKzgCommitment: (value) => kzg.blobToKzgCommitment(value),
      computeBlobKzgProof: (value, valueCommitment) => kzg.computeBlobKzgProof(value, valueCommitment),
      verifyKzgProof: (c, z, y, p) => kzg.verifyKzgProof(c, z, y, p),
      verifyBlobKzgProofBatch: (b, c, p) => kzg.verifyBlobKzgProofBatch(b, c, p),
    };
    const common = Common.custom(
      { chainId: 31337, name: "hardhat", networkId: 31337 },
      { hardfork: "cancun", customCrypto: { kzg: wrapper } }
    );
    const raw = BlobEIP4844Transaction.fromTxData({
      nonce: BigInt(await ethers.provider.getTransactionCount(wallet.address)),
      maxFeePerGas: baseFee * 2n + 1_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      gasLimit: 3_000_000n,
      to: batch.address.toLowerCase(),
      data: ethers.utils.arrayify(batch.interface.encodeFunctionData("submitMerkleRoot", [root, padded])),
      maxFeePerBlobGas: 1_000_000_000n,
      blobVersionedHashes: [Uint8Array.from(versionedHash)],
      blobs: [blob], kzgCommitments: [commitment], kzgProofs: [proof],
    }, { common }).sign(Buffer.from(identityP.privateKey.slice(2), "hex"));
    const txHash = await ethers.provider.send("eth_sendRawTransaction", ["0x" + Buffer.from(raw.serializeNetworkWrapper()).toString("hex")]);
    await network.provider.send("evm_mine", []);
    return ethers.provider.getTransactionReceipt(txHash);
  }

  it("fixes n, S, leaf values, and the padded root at registration time", async function () {
    const batch = await deployReadyBatch();
    const amounts = ["0.001", "0.002", "0.003"].map(ethers.utils.parseEther);
    const users = [alice, bob, carol];
    for (let i = 0; i < users.length; i++) {
      await batch.connect(users[i]).registerIntent(amounts[i], obligationCommitment(i));
    }

    expect(await batch.registeredCount()).to.equal(3);
    expect(await batch.registeredTotalAmount()).to.equal(ethers.utils.parseEther("0.006"));
    await expect(batch.connect(alice).registerIntent(amounts[0], obligationCommitment(9))).to.be.revertedWith("Already registered");
    await expect(batch.connect(deployer).registerIntent(0, obligationCommitment(9)))
      .to.be.revertedWith("Amount exceeds leaf cap");
    await expect(batch.connect(deployer).registerIntent(ethers.utils.parseEther("0.011"), obligationCommitment(9)))
      .to.be.revertedWith("Amount exceeds leaf cap");
    await expect(batch.connect(deployer).registerIntent(amounts[0], ethers.constants.HashZero))
      .to.be.revertedWith("Zero obligation commitment");

    const registrations = users.map((user, index) => ({
      addr: user.address, amount: amounts[index], commitment: obligationCommitment(index),
    }));
    const merkle = buildRegistrationTree(batch.address, registrations);
    expect(await batch.referenceRegistrationMerkleRoot(merkle.padded)).to.equal(merkle.root);
    expect(await batch.registrationAccumulatorRoot(merkle.padded)).to.equal(merkle.root);
    await asProver(async (prover) => {
      await expect(batch.connect(prover).callStatic.submitMerkleRoot(ethers.constants.HashZero, merkle.padded))
        .to.be.revertedWith("Root does not match registrations");
      await expect(batch.connect(prover).callStatic.submitMerkleRoot(merkle.root, 8))
        .to.be.revertedWith("Invalid padded batch size");
      const missing = buildRegistrationTree(batch.address, registrations.slice(0, 2));
      const reordered = buildRegistrationTree(batch.address, [registrations[1], registrations[0], registrations[2]]);
      const mutated = buildRegistrationTree(batch.address, [
        registrations[0], { ...registrations[1], amount: registrations[1].amount.add(1) }, registrations[2],
      ]);
      const commitmentMutated = buildRegistrationTree(batch.address, [
        registrations[0], { ...registrations[1], commitment: obligationCommitment(99) }, registrations[2],
      ]);
      const extra = buildRegistrationTree(batch.address, [
        ...registrations,
        { addr: deployer.address, amount: amounts[0], commitment: obligationCommitment(3) },
      ]);
      for (const invalidRoot of [missing.root, reordered.root, mutated.root, commitmentMutated.root, extra.root]) {
        await expect(batch.connect(prover).callStatic.submitMerkleRoot(invalidRoot, merkle.padded))
          .to.be.revertedWith("Root does not match registrations");
      }
    });

    await submitWithBlob(batch, merkle.root, merkle.padded);
    expect(await batch.realBatchSize()).to.equal(3);
    expect(await batch.paddedBatchSize()).to.equal(4);
    expect(await batch.perUserAllocation()).to.equal(ethers.utils.parseEther("1").div(3));
    const frozenN = await batch.registeredCount();
    const frozenS = await batch.registeredTotalAmount();
    const frozenPaddedN = await batch.paddedBatchSize();
    const frozenRoot = await batch.currentMerkleRoot();
    const frozenVmax = await batch.MAX_LEAF_AMOUNT();
    await expect(batch.connect(deployer).registerIntent(amounts[0], obligationCommitment(77)))
      .to.be.revertedWith("Root already submitted");
    expect(await batch.registeredCount()).to.equal(frozenN);
    expect(await batch.registeredTotalAmount()).to.equal(frozenS);
    expect(await batch.paddedBatchSize()).to.equal(frozenPaddedN);
    expect(await batch.currentMerkleRoot()).to.equal(frozenRoot);
    expect(await batch.MAX_LEAF_AMOUNT()).to.equal(frozenVmax);

    await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
    await network.provider.send("evm_mine", []);
    await expect(batch.connect(alice).claimWithMerkleProof(alice.address, amounts[0], proofFor(merkle.tree, 0), 0))
      .to.emit(batch, "leafClaimed");
    await expect(batch.connect(alice).claimWithMerkleProof(alice.address, amounts[0], proofFor(merkle.tree, 0), 1))
      .to.be.revertedWith("Leaf index not bound to registration");
    await expect(batch.connect(alice).claimWithMerkleProof(alice.address, amounts[0], proofFor(merkle.tree, 0), 0))
      .to.be.revertedWith("Already claimed");
    await expect(batch.connect(bob).claimWithMerkleProof(bob.address, amounts[1], proofFor(merkle.tree, 1), 3))
      .to.be.revertedWith("Index is not a claimable obligation");
    await expect(batch.connect(bob).claimWithMerkleProof(bob.address, amounts[1].add(1), proofFor(merkle.tree, 1), 1))
      .to.be.revertedWith("Leaf amount not bound to registration");
    await batch.connect(bob).claimWithMerkleProof(bob.address, amounts[1], proofFor(merkle.tree, 1), 1);
    await batch.connect(carol).claimWithMerkleProof(carol.address, amounts[2], proofFor(merkle.tree, 2), 2);

    let claimedRegisteredValue = ethers.constants.Zero;
    for (let index = 0; index < 3; index++) {
      if (await batch.isClaimed(index)) claimedRegisteredValue = claimedRegisteredValue.add((await batch.registrationAt(index)).amount);
    }
    expect(claimedRegisteredValue).to.equal(await batch.registeredTotalAmount());
  });

  it("rejects a root for an empty registration ledger", async function () {
    const batch = await deployReadyBatch();
    await asProver(async (prover) => {
      await expect(batch.connect(prover).callStatic.submitMerkleRoot(ethers.constants.HashZero, 1))
        .to.be.revertedWith("No registered obligations");
    });
  });

  it("matches the reference root at every R2 boundary through 256 registrations", async function () {
    this.timeout(180000);
    const create = await factory.createBatch(proverAddress, verifierAddress);
    const created = await create.wait();
    const batchAddress = created.events.find((event) => event.event === "BatchCreated").args.batch;
    const batch = await ethers.getContractAt("AuroraFull", batchAddress);
    const checkpoints = new Set([1, 2, 3, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256]);
    const registrations = [];
    let sum = ethers.constants.Zero;

    for (let i = 0; i < 256; i++) {
      const address = ethers.utils.getAddress(ethers.utils.hexZeroPad(ethers.utils.hexlify(0x1000 + i), 20));
      const amount = ethers.BigNumber.from((i % 10) + 1);
      const commitment = obligationCommitment(1000 + i);
      await registerAs(address, batch, amount, commitment);
      registrations.push({ addr: address, amount, commitment });
      sum = sum.add(amount);

      if (checkpoints.has(i + 1)) {
        const merkle = buildRegistrationTree(batch.address, registrations);
        expect(await batch.registeredCount()).to.equal(i + 1);
        expect(await batch.registeredTotalAmount()).to.equal(sum);
        expect(await batch.referenceRegistrationMerkleRoot(merkle.padded)).to.equal(merkle.root);
        expect(await batch.registrationAccumulatorRoot(merkle.padded)).to.equal(merkle.root);
      }
    }
  });

  it("accepts the same ledger root in reference and incremental submission paths", async function () {
    const Reference = await ethers.getContractFactory("AuroraFullReference");
    const referenceImplementation = await Reference.deploy();
    await referenceImplementation.deployed();
    const Factory = await ethers.getContractFactory("AuroraFactory");
    const referenceFactory = await Factory.deploy(referenceImplementation.address);
    await referenceFactory.deployed();
    const incremental = await deployReadyBatch();
    const reference = await deployReadyBatch(referenceFactory);
    const users = [alice, bob, carol];
    const amounts = [11, 12, 13].map(ethers.BigNumber.from);
    const registrations = users.map((user, index) => ({
      addr: user.address, amount: amounts[index], commitment: obligationCommitment(2000 + index),
    }));

    for (const batch of [incremental, reference]) {
      for (let i = 0; i < registrations.length; i++) {
        await batch.connect(users[i]).registerIntent(amounts[i], registrations[i].commitment);
      }
    }
    const incrementalTree = buildRegistrationTree(incremental.address, registrations);
    const referenceTree = buildRegistrationTree(reference.address, registrations);
    expect(await incremental.registrationAccumulatorRoot(incrementalTree.padded)).to.equal(incrementalTree.root);
    expect(await reference.referenceRegistrationMerkleRoot(referenceTree.padded)).to.equal(referenceTree.root);

    await submitWithBlob(incremental, incrementalTree.root, incrementalTree.padded);
    await submitWithBlob(reference, referenceTree.root, referenceTree.padded);
    expect(await incremental.currentMerkleRoot()).to.equal(incrementalTree.root);
    expect(await reference.currentMerkleRoot()).to.equal(referenceTree.root);
  });
});
