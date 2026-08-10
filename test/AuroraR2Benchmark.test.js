const { ethers, network } = require("hardhat");
const EthCrypto = require("eth-crypto");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/**
 * R2 benchmark harness.  It deliberately executes both root-selection paths
 * against the same registration ledger.  The printed JSON is an intermediate
 * experiment artifact; manuscript tables are updated only after review.
 */
describe("Aurora R2 - reference vs incremental lifecycle benchmark", function () {
  const CHALLENGE_WINDOW = 24 * 60 * 60;
  const T_CLAIM = 7 * 24 * 60 * 60;
  const CASES = [1, 16, 64, 128, 256, 3, 17, 65, 129];
  const LEAF_TYPEHASH = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index,bytes32 obligationCommitment)")
  );
  const DOMAIN_TYPEHASH = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
  );

  let deployer, testdata, identityP, identityV, proverAddress, verifierAddress;
  let incrementalFactory, referenceFactory, deploymentGas, kzg;

  function number(receipt) { return receipt.gasUsed.toNumber(); }
  function hashPair(left, right) {
    return ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32", "bytes32"], [left, right]));
  }
  function obligationCommitment(index) {
    return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`aurora-r2-benchmark-obligation-${index}`));
  }
  function domainSeparator(contractAddress) {
    return ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [DOMAIN_TYPEHASH, ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")), 31337, contractAddress]
    ));
  }
  function leafHash(contractAddress, entry, index) {
    const structHash = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "address", "uint256", "uint256", "bytes32"],
      [LEAF_TYPEHASH, entry.addr, entry.amount, index, entry.commitment]
    ));
    return ethers.utils.keccak256(ethers.utils.concat([
      ethers.utils.arrayify("0x1901"), ethers.utils.arrayify(domainSeparator(contractAddress)), ethers.utils.arrayify(structHash),
    ]));
  }
  function treeFor(contractAddress, registrations) {
    let padded = 1;
    while (padded < registrations.length) padded <<= 1;
    const dummy = ethers.utils.keccak256(ethers.utils.solidityPack(["string", "address"], ["AURORA_DUMMY", contractAddress]));
    let nodes = Array.from({ length: padded }, (_, index) =>
      index < registrations.length ? ethers.utils.keccak256(leafHash(contractAddress, registrations[index], index)) : dummy
    );
    const tree = [nodes];
    while (nodes.length > 1) {
      const next = [];
      for (let i = 0; i < nodes.length; i += 2) next.push(hashPair(nodes[i], nodes[i + 1]));
      tree.push(next);
      nodes = next;
    }
    return { padded, root: nodes[0], tree };
  }
  function proofFor(tree, index) {
    const proof = [];
    for (let level = 0, cursor = index; level < tree.length - 1; level++, cursor >>= 1) {
      proof.push(tree[level][cursor % 2 === 0 ? cursor + 1 : cursor - 1]);
    }
    return proof;
  }
  async function asAccount(address, fn) {
    await network.provider.send("hardhat_setBalance", [address, "0x1000000000000000000"]);
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [address] });
    try { return await fn(await ethers.getSigner(address)); }
    finally { await network.provider.request({ method: "hardhat_stopImpersonatingAccount", params: [address] }); }
  }
  async function submitWithBlob(contract, root, padded) {
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
    const kzgWrapper = {
      blobToKzgCommitment: (value) => kzg.blobToKzgCommitment(value),
      computeBlobKzgProof: (value, valueCommitment) => kzg.computeBlobKzgProof(value, valueCommitment),
      verifyKzgProof: (c, z, y, p) => kzg.verifyKzgProof(c, z, y, p),
      verifyBlobKzgProofBatch: (b, c, p) => kzg.verifyBlobKzgProofBatch(b, c, p),
    };
    const common = Common.custom({ chainId: 31337, name: "hardhat", networkId: 31337 }, { hardfork: "cancun", customCrypto: { kzg: kzgWrapper } });
    const signed = BlobEIP4844Transaction.fromTxData({
      nonce: BigInt(await ethers.provider.getTransactionCount(wallet.address)),
      maxFeePerGas: baseFee * 2n + 1_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      gasLimit: 3_000_000n,
      to: contract.address.toLowerCase(),
      data: ethers.utils.arrayify(contract.interface.encodeFunctionData("submitMerkleRoot", [root, padded])),
      maxFeePerBlobGas: 1_000_000_000n,
      blobVersionedHashes: [Uint8Array.from(versionedHash)], blobs: [blob], kzgCommitments: [commitment], kzgProofs: [proof],
    }, { common }).sign(Buffer.from(identityP.privateKey.slice(2), "hex"));
    const txHash = await network.provider.send("eth_sendRawTransaction", ["0x" + Buffer.from(signed.serializeNetworkWrapper()).toString("hex")]);
    await network.provider.send("evm_mine", []);
    return ethers.provider.getTransactionReceipt(txHash);
  }
  async function createReadyBatch(factory, contractName, poolValue) {
    const creation = await (await factory.createBatch(proverAddress, verifierAddress)).wait();
    const batchAddress = creation.events.find((event) => event.event === "BatchCreated").args.batch;
    const batch = await ethers.getContractAt(contractName, batchAddress);
    const funding = await (await deployer.sendTransaction({ to: batch.address, value: ethers.utils.parseEther("2") })).wait();
    const sigP = EthCrypto.sign(identityP.privateKey, testdata.setupMessageDigest);
    const sigV = EthCrypto.sign(identityV.privateKey, testdata.setupMessageDigest);
    const setup = await (await batch.setup(
      testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex,
      testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed,
      testdata.timelock, testdata.RelTimelock, sigP, sigV
    )).wait();
    const pool = await asAccount(proverAddress, async (prover) =>
      (await batch.connect(prover).depositUserPool({ value: poolValue })).wait()
    );
    return { batch, gas: { batchCreation: number(creation), funding: number(funding), setup: number(setup), pool: number(pool) } };
  }
  function registrationAddress(index) {
    return ethers.utils.getAddress(ethers.utils.hexZeroPad(ethers.utils.hexlify(0x2000 + index), 20));
  }

  before(async function () {
    this.timeout(120000);
    [deployer] = await ethers.getSigners();
    testdata = require("../data/jsonTestData.json");
    identityP = EthCrypto.createIdentity(Buffer.from("aurora-r2-benchmark-prover".repeat(8)));
    identityV = EthCrypto.createIdentity(Buffer.from("aurora-r2-benchmark-verifier".repeat(8)));
    proverAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityP.privateKey));
    verifierAddress = EthCrypto.publicKey.toAddress(EthCrypto.publicKeyByPrivateKey(identityV.privateKey));
    const Incremental = await ethers.getContractFactory("AuroraFull");
    const Reference = await ethers.getContractFactory("AuroraFullReference");
    const Factory = await ethers.getContractFactory("AuroraFactory");
    const incremental = await Incremental.deploy();
    const incrementalReceipt = await incremental.deployTransaction.wait();
    const reference = await Reference.deploy();
    const referenceReceipt = await reference.deployTransaction.wait();
    incrementalFactory = await Factory.deploy(incremental.address);
    const incrementalFactoryReceipt = await incrementalFactory.deployTransaction.wait();
    referenceFactory = await Factory.deploy(reference.address);
    const referenceFactoryReceipt = await referenceFactory.deployTransaction.wait();
    deploymentGas = {
      incrementalImplementation: number(incrementalReceipt), referenceImplementation: number(referenceReceipt),
      incrementalFactory: number(incrementalFactoryReceipt), referenceFactory: number(referenceFactoryReceipt),
    };
  });

  it("measures the full R2 lifecycle without changing manuscript results", async function () {
    this.timeout(1800000);
    const results = [];
    const blockLimit = (await ethers.provider.getBlock("latest")).gasLimit.toNumber();
    for (const n of CASES) {
      for (const variant of [
        { name: "incremental", factory: incrementalFactory, contractName: "AuroraFull" },
        { name: "reference", factory: referenceFactory, contractName: "AuroraFullReference" },
      ]) {
        const snapshot = await network.provider.send("evm_snapshot");
        const registrations = Array.from({ length: n }, (_, index) => ({
          addr: registrationAddress(index), amount: ethers.BigNumber.from(1), commitment: obligationCommitment(index),
        }));
        const totalValue = ethers.BigNumber.from(n);
        const { batch, gas } = await createReadyBatch(variant.factory, variant.contractName, totalValue);
        const registerReceipts = [];
        for (const entry of registrations) {
          registerReceipts.push(await asAccount(entry.addr, async (user) =>
            (await batch.connect(user).registerIntent(entry.amount, entry.commitment)).wait()
          ));
        }
        const merkle = treeFor(batch.address, registrations);
        const referenceRoot = await batch.referenceRegistrationMerkleRoot(merkle.padded);
        const incrementalRoot = await batch.registrationAccumulatorRoot(merkle.padded);
        if (referenceRoot !== merkle.root || incrementalRoot !== merkle.root) throw new Error("R2 root oracle mismatch");
        const submission = await submitWithBlob(batch, merkle.root, merkle.padded);
        await network.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
        await network.provider.send("evm_mine", []);
        const claims = [];
        for (let index = 0; index < n; index++) {
          const entry = registrations[index];
          claims.push(await asAccount(entry.addr, async (user) =>
            (await batch.connect(user).claimWithMerkleProof(entry.addr, entry.amount, proofFor(merkle.tree, index), index)).wait()
          ));
        }
        await network.provider.send("evm_increaseTime", [T_CLAIM + 1]);
        await network.provider.send("evm_mine", []);
        const settlement = await (await batch.settle()).wait();
        const registerGas = registerReceipts.reduce((sum, receipt) => sum + number(receipt), 0);
        const claimGas = claims.reduce((sum, receipt) => sum + number(receipt), 0);
        const lifecycleGas = gas.batchCreation + gas.funding + gas.setup + gas.pool + registerGas + number(submission) + claimGas + number(settlement);
        const maxReceiptGas = Math.max(...registerReceipts.map(number), number(submission), ...claims.map(number), number(settlement));
        results.push({
          variant: variant.name, n, paddedN: merkle.padded, padding: merkle.padded - n,
          batchCreationGas: gas.batchCreation, registerGasTotal: registerGas, registerGasPerObligation: Math.round(registerGas / n),
          rootSubmissionGas: number(submission), firstClaimGas: number(claims[0]), subsequentClaimGas: n > 1 ? number(claims[1]) : null,
          settleGas: number(settlement), lifecycleGas, lifecycleGasPerObligation: Math.round(lifecycleGas / n),
          userGas: registerGas + claimGas, proverGas: gas.pool + number(submission), maxReceiptGas,
          exceedsBlockGasLimit: maxReceiptGas > blockLimit,
        });
        await network.provider.send("evm_revert", [snapshot]);
      }
    }
    const artifact = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      environment: {
        network: network.name,
        chainId: (await ethers.provider.getNetwork()).chainId,
        execution: "Hardhat local network",
      },
      blockLimit,
      deploymentGas,
      results,
    };
    console.log("R2_BENCHMARK_JSON=" + JSON.stringify(artifact));
    if (process.env.AURORA_BENCHMARK_OUT) {
      const outputPath = path.resolve(process.env.AURORA_BENCHMARK_OUT);
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`);
      console.log(`R2_BENCHMARK_ARTIFACT=${outputPath}`);
    }
  });
});
