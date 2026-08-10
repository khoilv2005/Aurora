const path = require("path");
const { ethers } = require("hardhat");
const EthCrypto = require("eth-crypto");
const testdata = require(path.resolve(__dirname, "../../../data/jsonTestData.json"));
const disputeVectors = require(path.resolve(__dirname, "../../../data/sepoliaDisputeVectors.json"));
const { SECONDS, STATE_EVENT_CODES } = require("./constants");
const {
  loadConfig,
  loadState,
  mergeState,
  writeStepArtifact,
  explorerLinks,
  getScenarioContext,
  getSharedDeploymentPath,
  writeJson,
  readJson,
} = require("./scenario");
const { loadOrCreateActors, ensureFunded } = require("./actors");
const { buildMerkleTree712, getMerkleProof712 } = require("./merkle712");
const { obligationCommitment, buildRegistrationTree, proofFor } = require("./merkleR2");

function bnToString(value) {
  if (value == null) return null;
  return ethers.BigNumber.isBigNumber(value) ? value.toString() : String(value);
}

function signDigestWithActor(actor, digest) {
  if (actor && actor.privateKey) {
    return EthCrypto.sign(actor.privateKey, digest);
  }
  return ethers.utils.joinSignature(actor.signer._signingKey().signDigest(digest));
}

function serializable(value) {
  if (ethers.BigNumber.isBigNumber(value)) return value.toString();
  if (Array.isArray(value)) return value.map(serializable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, serializable(val)]));
  }
  return value;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRateLimited(error) {
  const message = String(error && (error.message || error));
  return /too many requests|rate limit|429/i.test(message);
}

async function withRpcRetry(action, attempts = 6) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await action();
    } catch (error) {
      lastError = error;
      if (!isRateLimited(error) || attempt === attempts - 1) throw error;
      await sleep(500 * (attempt + 1));
    }
  }
  throw lastError;
}

async function waitForReceiptWithMetrics(txPromise) {
  const startMs = Date.now();
  const tx = await txPromise;
  const receipt = await withRpcRetry(() => tx.wait());
  const endMs = Date.now();
  const block = await withRpcRetry(() => ethers.provider.getBlock(receipt.blockNumber));
  return {
    tx,
    receipt,
    block,
    latencyMs: endMs - startMs,
  };
}

function summarizeReceipt(networkName, label, detail) {
  const { tx, receipt, block, latencyMs } = detail;
  return {
    label,
    txHash: tx.hash,
    txLink: explorerLinks(networkName, tx.hash, "tx"),
    from: tx.from,
    to: tx.to,
    gasUsed: bnToString(receipt.gasUsed),
    effectiveGasPrice: bnToString(receipt.effectiveGasPrice || 0),
    gasCostWei: bnToString((receipt.effectiveGasPrice || ethers.constants.Zero).mul(receipt.gasUsed)),
    blockNumber: receipt.blockNumber,
    blockTimestamp: block.timestamp,
    latencyMs,
    status: receipt.status,
    eventNames: (receipt.events || []).map((event) => event.event).filter(Boolean),
  };
}

async function runInBatches(items, width, callback, interBatchDelayMs = 0) {
  const results = [];
  for (let start = 0; start < items.length; start += width) {
    const chunk = items.slice(start, start + width);
    const chunkResults = await Promise.all(chunk.map(callback));
    results.push(...chunkResults);
    if (interBatchDelayMs > 0 && start + width < items.length) await sleep(interBatchDelayMs);
  }
  return results;
}

async function fundSharedUsersOnce({ funder, users, targetBalance, minimumBalance, networkName, parallelism }) {
  const rpcParallelism = Math.min(parallelism, 4);
  const balances = await runInBatches(users, rpcParallelism, (user) => withRpcRetry(() => user.signer.getBalance()));
  const needsFunding = users
    .map((user, index) => ({ user, balance: balances[index] }))
    .filter(({ balance }) => balance.lt(minimumBalance));
  if (!needsFunding.length) return [];

  let nextNonce = await withRpcRetry(() => ethers.provider.getTransactionCount(funder.address, "pending"));
  // These transfers share one sender.  Submit them in nonce order: a few RPC
  // providers accept parallel submissions out of order as replacements even
  // when explicit nonces are supplied.  Receipt collection remains batched,
  // so this only affects the short submission phase and keeps every funding
  // transaction independently traceable.
  const submitted = [];
  for (const { user, balance } of needsFunding) {
    const nonce = nextNonce++;
    const tx = await funder.sendTransaction({
      to: user.address,
      value: targetBalance.sub(balance),
      nonce,
    });
    submitted.push({ user, tx });
  }
  return runInBatches(submitted, rpcParallelism, async ({ user, tx }) => {
    const detail = await waitForReceiptWithMetrics(Promise.resolve(tx));
    return summarizeReceipt(networkName, `fundSharedUser:${user.address}`, detail);
  });
}

function getFutureSetupParams(config, actors) {
  if (config.useBenchmarkSetupDigest) {
    const digest = testdata.setupMessageDigest;
    const sigP = signDigestWithActor(actors.prover, digest);
    const sigV = signDigestWithActor(actors.verifier, digest);
    return {
      digest,
      args: [
        testdata.fundingTxId,
        testdata.fundingTx_LockingScript,
        testdata.fundingTxIndex,
        testdata.sighash_all,
        testdata.pkProverUnprefixedUncompressed,
        testdata.pkVerifierUnprefixedUncompressed,
        testdata.timelock,
        testdata.RelTimelock,
        sigP,
        sigV,
      ],
    };
  }

  const timelock = config.futureSetupTimelock || disputeVectors.futureSetupTimelock;
  const timelockDisp = config.relTimelock || disputeVectors.relTimelock;
  const parts = [
    testdata.fundingTxId,
    testdata.fundingTx_LockingScript,
    testdata.fundingTxIndex,
    testdata.sighash_all,
    testdata.pkProverUnprefixedUncompressed,
    testdata.pkVerifierUnprefixedUncompressed,
    ethers.utils.hexZeroPad(ethers.utils.hexlify(timelock), 32),
    ethers.utils.hexZeroPad(ethers.utils.hexlify(timelockDisp), 32),
  ];
  const digest = ethers.utils.sha256(ethers.utils.hexConcat(parts));
  const sigP = signDigestWithActor(actors.prover, digest);
  const sigV = signDigestWithActor(actors.verifier, digest);
  return {
    digest,
    args: [
      testdata.fundingTxId,
      testdata.fundingTx_LockingScript,
      testdata.fundingTxIndex,
      testdata.sighash_all,
      testdata.pkProverUnprefixedUncompressed,
      testdata.pkVerifierUnprefixedUncompressed,
      timelock,
      timelockDisp,
      sigP,
      sigV,
    ],
  };
}

async function getContext(scenarioDir) {
  const config = loadConfig(scenarioDir);
  const state = loadState(scenarioDir);
  const provider = ethers.provider;
  const network = await provider.getNetwork();
  const networkName = network.name || "unknown";
  const actors = await loadOrCreateActors(scenarioDir, config, provider);
  return { config, state, actors, provider, networkName };
}

async function getBatchContract(batchAddress, signer) {
  return ethers.getContractAt("AuroraFullTestnet", batchAddress, signer);
}

async function captureBalances(addresses) {
  const result = {};
  for (const [label, address] of Object.entries(addresses)) {
    if (!address) continue;
    result[label] = (await ethers.provider.getBalance(address)).toString();
  }
  return result;
}

async function deployBatch(scenarioDir, stepName) {
  const { config, actors, networkName } = await getContext(scenarioDir);
  const sharedDeploymentKey = config.sharedDeploymentKey;
  if (!sharedDeploymentKey) {
    throw new Error(`Scenario ${config.scenarioId || scenarioDir} must define sharedDeploymentKey`);
  }
  const sharedPath = getSharedDeploymentPath(networkName, sharedDeploymentKey);
  const shared = readJson(sharedPath, null);
  if (!shared || !shared.implementationAddress || !shared.factoryAddress) {
    throw new Error(`Missing shared deployment at ${sharedPath}. Run shared bootstrap first.`);
  }
  const deployedImpl = await ethers.getContractAt("AuroraFullTestnet", shared.implementationAddress, actors.deployer.signer);
  const factory = await ethers.getContractAt("AuroraFactory", shared.factoryAddress, actors.deployer.signer);

  const createBatch = await waitForReceiptWithMetrics(
    factory.connect(actors.deployer.signer).createBatch(actors.prover.address, actors.verifier.address)
  );
  const batchCreated = (createBatch.receipt.events || []).find((event) => event.event === "BatchCreated");
  const batchAddress = batchCreated.args.batch;

  mergeState(scenarioDir, {
    scenarioId: config.scenarioId,
    networkName,
    implementationAddress: deployedImpl.address,
    factoryAddress: factory.address,
    batchAddress,
    proverAddress: actors.prover.address,
    verifierAddress: actors.verifier.address,
    userAddresses: actors.users.map((user) => user.address),
  });

  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      implementationAddress: deployedImpl.address,
      implementationLink: explorerLinks(networkName, deployedImpl.address, "address"),
      factoryAddress: factory.address,
      factoryLink: explorerLinks(networkName, factory.address, "address"),
      batchAddress,
      batchLink: explorerLinks(networkName, batchAddress, "address"),
      reusedSharedDeployment: true,
      sharedDeploymentKey,
    },
    transactions: [summarizeReceipt(networkName, "createBatch", createBatch)],
    actors: {
      deployer: actors.deployer.address,
      prover: actors.prover.address,
      verifier: actors.verifier.address,
      users: actors.users.map((user) => user.address),
    },
  });
}

async function deploySharedInfra(scenarioDir, stepName) {
  const { config, actors, networkName } = await getContext(scenarioDir);
  const sharedDeploymentKey = config.sharedDeploymentKey || "default";
  const sharedPath = getSharedDeploymentPath(networkName, sharedDeploymentKey);

  // Deploy AuroraHelperExt as external library first (required by AuroraFullTestnet)
  const libFactory = await ethers.getContractFactory("AuroraHelperExt", actors.deployer.signer);
  const deployedLib = await libFactory.deploy();
  const libDeploy = await waitForReceiptWithMetrics(Promise.resolve(deployedLib.deployTransaction));

  const implFactory = await ethers.getContractFactory("AuroraFullTestnet", {
    signer: actors.deployer.signer,
    libraries: { AuroraHelperExt: deployedLib.address },
  });
  const deployedImpl = await implFactory.deploy();
  const implementation = await waitForReceiptWithMetrics(Promise.resolve(deployedImpl.deployTransaction));

  const factoryFactory = await ethers.getContractFactory("AuroraFactory", actors.deployer.signer);
  const factory = await factoryFactory.deploy(deployedImpl.address);
  const factoryDeploy = await waitForReceiptWithMetrics(Promise.resolve(factory.deployTransaction));

  writeJson(sharedPath, {
    networkName,
    sharedDeploymentKey,
    libAddress: deployedLib.address,
    implementationAddress: deployedImpl.address,
    factoryAddress: factory.address,
    libDeployTxHash: libDeploy.tx.hash,
    implementationDeployTxHash: implementation.tx.hash,
    factoryDeployTxHash: factoryDeploy.tx.hash,
    recordedAt: new Date().toISOString(),
  });

  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      sharedDeploymentKey,
      sharedDeploymentPath: sharedPath,
      libAddress: deployedLib.address,
      libLink: explorerLinks(networkName, deployedLib.address, "address"),
      implementationAddress: deployedImpl.address,
      implementationLink: explorerLinks(networkName, deployedImpl.address, "address"),
      factoryAddress: factory.address,
      factoryLink: explorerLinks(networkName, factory.address, "address"),
    },
    transactions: [
      summarizeReceipt(networkName, "deployAuroraHelperExt", libDeploy),
      summarizeReceipt(networkName, "deployImplementation", implementation),
      summarizeReceipt(networkName, "deployFactory", factoryDeploy),
    ],
  });
}

async function fundAndSetup(scenarioDir, stepName, options = {}) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const txs = [];
  const proverFunding = ethers.utils.parseEther(options.proverFundingEth || config.proverFundingEth || "5.0");
  const verifierFunding = ethers.utils.parseEther(options.verifierFundingEth || config.verifierFundingEth || "5.0");
  const actorFunding = ethers.utils.parseEther(config.userFundingEth || "0.05");
  const gasBuffer = ethers.utils.parseEther(config.gasBufferEth || "0.01");
  const sharedPoolMode = Boolean(config.sharedActorPool);
  const sharedUserMinimum = ethers.utils.parseEther(config.sharedUserMinimumEth || "0.001");
  const parallelism = Number(config.txParallelism || 16);

  const proverTopUp = await ensureFunded(actors.deployer.signer, actors.prover.signer, proverFunding.add(gasBuffer));
  if (proverTopUp) {
    txs.push(summarizeReceipt(networkName, "fundProver", await waitForReceiptWithMetrics(Promise.resolve(proverTopUp))));
  }

  const verifierTopUp = await ensureFunded(actors.deployer.signer, actors.verifier.signer, verifierFunding.add(actorFunding).add(gasBuffer));
  if (verifierTopUp) {
    txs.push(summarizeReceipt(networkName, "fundVerifier", await waitForReceiptWithMetrics(Promise.resolve(verifierTopUp))));
  }
  if (sharedPoolMode) {
    txs.push(...await fundSharedUsersOnce({
      funder: actors.deployer.signer,
      users: actors.users,
      targetBalance: actorFunding.add(gasBuffer),
      minimumBalance: sharedUserMinimum,
      networkName,
      parallelism,
    }));
  } else {
    for (const user of actors.users) {
      const fundTx = await ensureFunded(actors.deployer.signer, user.signer, actorFunding.add(gasBuffer));
      if (fundTx) {
        txs.push(summarizeReceipt(networkName, `fundUser:${user.address}`, await waitForReceiptWithMetrics(Promise.resolve(fundTx))));
      }
    }
  }

  const lockP = await waitForReceiptWithMetrics(
    actors.prover.signer.sendTransaction({ to: state.batchAddress, value: proverFunding })
  );
  const lockV = await waitForReceiptWithMetrics(
    actors.verifier.signer.sendTransaction({ to: state.batchAddress, value: verifierFunding })
  );
  txs.push(summarizeReceipt(networkName, "lockProver", lockP));
  txs.push(summarizeReceipt(networkName, "lockVerifier", lockV));

  if (!options.skipSetup) {
    const setupParams = getFutureSetupParams(config, actors);
    const setupTx = await waitForReceiptWithMetrics(batch.connect(actors.prover.signer).setup(...setupParams.args));
    txs.push(summarizeReceipt(networkName, "setup", setupTx));
    mergeState(scenarioDir, {
      setupDigest: setupParams.digest,
      setupTimelock: String(setupParams.args[6]),
      setupRelTimelock: String(setupParams.args[7]),
    });
  }

  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      batchAddress: state.batchAddress,
      batchLink: explorerLinks(networkName, state.batchAddress, "address"),
      setupSkipped: !!options.skipSetup,
    },
    balancesAfter: await captureBalances({
      prover: actors.prover.address,
      verifier: actors.verifier.address,
      batch: state.batchAddress,
    }),
    transactions: txs,
  });
}

async function registerUsers(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const txs = [];
  let registrationFundingTransactions = [];
  const isR2 = config.protocolVersion === "r2";
  const amount = ethers.utils.parseEther(config.leafAmountEth || "0.001");
  const users = isR2 ? actors.users.slice(0, config.batchSize || actors.users.length) : actors.users;
  if (isR2 && users.length !== (config.batchSize || users.length)) {
    throw new Error("R2 requires one distinct registered user for each real obligation");
  }
  if (isR2 && config.sharedActorPool) {
    // Reused test accounts spend their own gas in every batch.  Restore only
    // the small envelope needed to submit the next registration, rather than
    // pre-funding every scenario with a new R1-sized allocation.
    const registrationGasFloor = ethers.utils.parseEther(config.registrationFundingEth || "0.002");
    registrationFundingTransactions = await fundSharedUsersOnce({
      funder: actors.deployer.signer,
      users,
      targetBalance: registrationGasFloor,
      minimumBalance: registrationGasFloor,
      networkName,
      parallelism: Number(config.txParallelism || 16),
    });
  }
  const parallelism = Math.min(Number(config.txParallelism || 1), 4);
  const registerGasLimit = Number(config.registerGasLimit || 220000);
  const registerTxOverrides = {
    gasLimit: registerGasLimit,
    // A modest fixed fee envelope prevents a single user transaction from
    // remaining pending and blocking a four-account registration group.  The
    // artifact always reports the effective price actually paid, not this cap.
    maxPriorityFeePerGas: ethers.utils.parseUnits(config.registerPriorityFeeGwei || "2", "gwei"),
    maxFeePerGas: ethers.utils.parseUnits(config.registerMaxFeeGwei || "8", "gwei"),
  };
  const submissions = await runInBatches(users.map((user, index) => ({ user, index })), parallelism, async ({ user, index }) => {
    const batch = await getBatchContract(state.batchAddress, user.signer);
    // A resumed full-matrix run must not re-register accounts which were
    // already accepted before a transient RPC or estimation failure.
    if (isR2 && !(await batch.registrationIndexPlusOne(user.address)).isZero()) {
      return null;
    }
    const startedAt = Date.now();
    const tx = isR2
      // Estimation made while several registrations are pending can reflect a
      // cheaper frontier height than the eventual execution.  This cap covers
      // the measured R2 worst case; gas paid remains receipt.gasUsed.
      ? await batch.registerIntent(amount, obligationCommitment(index), registerTxOverrides)
      : await batch.registerIntent();
    return { user, tx, startedAt };
  }, 100);
  const registrations = await runInBatches(submissions.filter(Boolean), parallelism, async ({ user, tx, startedAt }) => {
    const detail = await waitForReceiptWithMetrics(Promise.resolve(tx));
    detail.latencyMs = Date.now() - startedAt;
    return summarizeReceipt(networkName, `registerIntent:${user.address}`, detail);
  });
  if (isR2) {
    // Reconstruct the complete accepted-registration ledger from events.  This
    // keeps the gas artifact complete if a resumable run had accepted some
    // registrations before its preceding process stopped.
    const observer = await getBatchContract(state.batchAddress, actors.deployer.signer);
    const deployArtifact = readJson(path.join(getScenarioContext(scenarioDir).artifactsDir, "01_deploy.json"), {});
    const deploymentBlock = Number(deployArtifact.transactions && deployArtifact.transactions[0] && deployArtifact.transactions[0].blockNumber);
    const latestBlock = await ethers.provider.getBlockNumber();
    const events = [];
    // The configured Sepolia RPC permits at most ten blocks per eth_getLogs
    // request.  Scanning from this batch's deployment block also makes the
    // recovery ledger precise instead of querying the chain from genesis.
    for (let fromBlock = deploymentBlock; fromBlock <= latestBlock; fromBlock += 10) {
      const toBlock = Math.min(fromBlock + 9, latestBlock);
      events.push(...await withRpcRetry(() => observer.queryFilter(observer.filters.UserRegistered(), fromBlock, toBlock)));
    }
    const eventTxs = await runInBatches(events, 4, async (event) => {
      const [tx, receipt, block] = await Promise.all([
        ethers.provider.getTransaction(event.transactionHash),
        ethers.provider.getTransactionReceipt(event.transactionHash),
        ethers.provider.getBlock(event.blockNumber),
      ]);
      return summarizeReceipt(networkName, `registerIntent:${event.args.user}`, {
        tx,
        receipt,
        block,
        latencyMs: null,
      });
    });
    txs.push(...eventTxs.sort((left, right) => left.blockNumber - right.blockNumber));
  } else {
    txs.push(...registrations.filter(Boolean));
  }
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      registeredUsers: users.length,
      protocolVersion: isR2 ? "r2" : "r1",
      avgRegisterGas: txs.length
        ? Math.round(txs.reduce((sum, tx) => sum + Number(tx.gasUsed), 0) / txs.length)
        : 0,
    },
    transactions: txs,
    registrationFundingTransactions,
  });
}

async function depositUserPool(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const value = ethers.utils.parseEther(config.depositUserPoolEth || "2.5");
  const gasBuffer = ethers.utils.parseEther(config.gasBufferEth || "0.01");
  const topUp = await ensureFunded(actors.deployer.signer, actors.prover.signer, value.add(gasBuffer));
  if (topUp) await (await Promise.resolve(topUp)).wait();
  const detail = await waitForReceiptWithMetrics(
    batch.connect(actors.prover.signer).depositUserPool({ value })
  );
  mergeState(scenarioDir, { userProtectionPoolDepositWei: value.toString() });
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      depositedWei: value.toString(),
      depositedEth: ethers.utils.formatEther(value),
    },
    transactions: [summarizeReceipt(networkName, "depositUserPool", detail)],
  });
}

async function expectRevert(label, action) {
  try {
    await action();
  } catch (error) {
    return { label, reverted: true, reason: error.reason || error.errorName || error.message };
  }
  throw new Error(`Expected ${label} to revert`);
}

async function r2Registrations(config, actors, batch) {
  const batchSize = config.batchSize || actors.users.length;
  if (actors.users.length < batchSize) throw new Error("R2 requires one actor per registered obligation");
  const count = await withRpcRetry(() => batch.registeredCount());
  if (!count.eq(batchSize)) throw new Error(`Expected ${batchSize} R2 registrations but found ${count.toString()}`);
  return runInBatches(Array.from({ length: batchSize }, (_, index) => index), 4, async (index) => {
    const entry = await withRpcRetry(() => batch.registrationAt(index));
    return {
      addr: entry.user,
      amount: ethers.BigNumber.from(entry.amount),
      obligationCommitment: entry.obligationCommitment,
    };
  }, 100);
}

async function validateR2PreSubmit(scenarioDir, stepName) {
  const { config, state, actors, networkName, provider } = await getContext(scenarioDir);
  if (config.protocolVersion !== "r2") throw new Error("validateR2PreSubmit is only valid for R2 scenarios");
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const registrations = await r2Registrations(config, actors, batch);
  const chainId = (await provider.getNetwork()).chainId;
  const expected = buildRegistrationTree(chainId, state.batchAddress, registrations);
  const count = await batch.registeredCount();
  const total = await batch.registeredTotalAmount();
  const expectedTotal = registrations.reduce((sum, entry) => sum.add(entry.amount), ethers.constants.Zero);
  if (!count.eq(registrations.length) || !total.eq(expectedTotal)) throw new Error("R2 registered-count or total-value invariant failed");
  if ((await batch.referenceRegistrationMerkleRoot(expected.padded)) !== expected.root) throw new Error("Reference registration root mismatch");
  if ((await batch.registrationAccumulatorRoot(expected.padded)) !== expected.root) throw new Error("Incremental registration root mismatch");

  const extra = ethers.Wallet.createRandom().connect(provider);
  const max = await batch.MAX_LEAF_AMOUNT();
  const reordered = registrations.length > 1
    ? buildRegistrationTree(chainId, state.batchAddress, [registrations[1], registrations[0], ...registrations.slice(2)])
    : { root: ethers.constants.HashZero };
  const mutated = buildRegistrationTree(chainId, state.batchAddress, [
    { ...registrations[0], amount: registrations[0].amount.add(1) }, ...registrations.slice(1),
  ]);
  const checks = await Promise.all([
    expectRevert("zero amount", () => batch.connect(extra).callStatic.registerIntent(0, obligationCommitment(700))),
    expectRevert("amount above Vmax", () => batch.connect(extra).callStatic.registerIntent(max.add(1), obligationCommitment(701))),
    expectRevert("duplicate registration", () => batch.connect(actors.users[0].signer).callStatic.registerIntent(registrations[0].amount, obligationCommitment(702))),
    expectRevert(registrations.length > 1 ? "reordered root" : "mismatched root", () => batch.connect(actors.prover.signer).callStatic.submitMerkleRoot(reordered.root, expected.padded)),
    expectRevert("mutated leaf root", () => batch.connect(actors.prover.signer).callStatic.submitMerkleRoot(mutated.root, expected.padded)),
  ]);
  mergeState(scenarioDir, { expectedR2Root: expected.root, expectedR2PaddedSize: expected.padded, expectedR2TotalWei: expectedTotal.toString() });
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { registeredCount: count.toString(), totalCommittedValueWei: total.toString(), paddedBatchSize: expected.padded, root: expected.root },
    checks,
  });
}

async function validateR2PostSubmit(scenarioDir, stepName) {
  const { config, state, actors, networkName, provider } = await getContext(scenarioDir);
  if (config.protocolVersion !== "r2") throw new Error("validateR2PostSubmit is only valid for R2 scenarios");
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const count = await batch.registeredCount();
  const total = await batch.registeredTotalAmount();
  const padded = await batch.paddedBatchSize();
  const root = await batch.currentMerkleRoot();
  if (root !== state.expectedR2Root || !count.eq(config.batchSize) || !total.eq(state.expectedR2TotalWei) || !padded.eq(state.expectedR2PaddedSize)) {
    throw new Error("R2 ledger-freeze invariant failed after submission");
  }
  const extra = ethers.Wallet.createRandom().connect(provider);
  const checks = [await expectRevert("post-submit registration", () =>
    batch.connect(extra).callStatic.registerIntent(ethers.utils.parseEther(config.leafAmountEth || "0.001"), obligationCommitment(703))
  )];
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { registeredCount: count.toString(), totalCommittedValueWei: total.toString(), paddedBatchSize: padded.toString(), root },
    checks,
  });
}

function buildScenarioLeaves(config, state, actors) {
  const amount = ethers.utils.parseEther(config.leafAmountEth || "0.01");
  const batchSize = config.batchSize || actors.users.length;
  const invalidLeaf = config.invalidLeaf || null;
  const sharedClaimer = config.sharedClaimer && actors.users.length > 0 ? actors.users[0].address : null;
  const leaves = [];
  for (let i = 0; i < batchSize; i++) {
    let addr = sharedClaimer || (actors.users[i] ? actors.users[i].address : actors.deployer.address);
    let leafAmount = amount;
    let isInvalid = false;
    if (invalidLeaf && i === invalidLeaf.index) {
      if (invalidLeaf.type === "zero-address") addr = ethers.constants.AddressZero;
      if (invalidLeaf.type === "zero-amount") leafAmount = ethers.constants.Zero;
      isInvalid = true;
    }
    leaves.push({ index: i, addr, amount: leafAmount, isInvalid });
  }
  return leaves;
}


async function waitCheckpoint(scenarioDir, stepName, kind) {
  const state = loadState(scenarioDir);
  const config = loadConfig(scenarioDir);
  const latestBlock = await ethers.provider.getBlock("latest");
  const submittedAt = Number(state.batchSubmitBlockTimestamp || 0);
  const extensionCount = Number(state.extensionCount || 0);
  const extendedWindow = SECONDS.challengeWindow + extensionCount * 86400;
  const extra = kind === "claim" ? extendedWindow : extendedWindow + SECONDS.claimWindow;
  const target = submittedAt + extra;
  const remainingSeconds = Math.max(0, target - latestBlock.timestamp);
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      kind,
      path: config.path,
      currentBlockTimestamp: latestBlock.timestamp,
      targetTimestamp: target,
      remainingSeconds,
      remainingHours: Number((remainingSeconds / 3600).toFixed(2)),
      extensionCount,
    },
  });
}

async function claimUsers(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const ctx = getScenarioContext(scenarioDir);
  const merkle = readJson(ctx.merklePath, null);
  if (!merkle) throw new Error("Missing merkle artifact; run submit-root first");
  const claimCount = Math.min(config.claimCount || actors.users.length, merkle.leaves.filter((leaf) => !leaf.isInvalid).length);
  const txs = [];
  let claimFundingTransactions = [];
  const candidates = [];
  for (const leaf of merkle.leaves) {
    if (leaf.isInvalid || candidates.length >= claimCount) continue;
    const user = actors.users.find((entry) => entry.address.toLowerCase() === leaf.addr.toLowerCase());
    if (!user) continue;
    const batch = await getBatchContract(state.batchAddress, user.signer);
    const alreadyClaimed = await withRpcRetry(() => batch.isClaimed(leaf.index));
    if (alreadyClaimed) continue;
    candidates.push({ leaf, user, batch });
  }

  if (config.sharedActorPool && candidates.length) {
    const claimGasFloor = ethers.utils.parseEther(config.claimFundingEth || "0.002");
    claimFundingTransactions = await fundSharedUsersOnce({
      funder: actors.deployer.signer,
      users: candidates.map((candidate) => candidate.user),
      targetBalance: claimGasFloor,
      minimumBalance: claimGasFloor,
      networkName,
      parallelism: Number(config.txParallelism || 16),
    });
  }

  const claimOverrides = {
    gasLimit: Number(config.claimGasLimit || 200000),
    maxPriorityFeePerGas: ethers.utils.parseUnits(config.claimPriorityFeeGwei || "2", "gwei"),
    maxFeePerGas: ethers.utils.parseUnits(config.claimMaxFeeGwei || "8", "gwei"),
  };
  const queuedClaims = await runInBatches(candidates, 4, async ({ leaf, user, batch }) => {
    const startedAt = Date.now();
    const tx = await batch.claimWithMerkleProof(
      leaf.addr,
      leaf.amount,
      leaf.proof,
      leaf.index,
      claimOverrides
    );
    return { leaf, user, tx, startedAt };
  }, 100);

  const claimReceipts = await runInBatches(queuedClaims, 4, async (item) => {
    const receipt = await withRpcRetry(() => item.tx.wait());
    const block = await withRpcRetry(() => ethers.provider.getBlock(receipt.blockNumber));
    return {
      label: `claim:${item.leaf.index}`,
      txHash: item.tx.hash,
      txLink: explorerLinks(networkName, item.tx.hash, "tx"),
      from: item.tx.from,
      to: item.tx.to,
      gasUsed: bnToString(receipt.gasUsed),
      effectiveGasPrice: bnToString(receipt.effectiveGasPrice || 0),
      gasCostWei: bnToString((receipt.effectiveGasPrice || ethers.constants.Zero).mul(receipt.gasUsed)),
      blockNumber: receipt.blockNumber,
      blockTimestamp: block.timestamp,
      latencyMs: Date.now() - item.startedAt,
      status: receipt.status,
      eventNames: (receipt.events || []).map((event) => event.event).filter(Boolean),
    };
  });
  txs.push(...claimReceipts);

  const claimTransactions = txs.filter((tx) => tx.label && tx.label.startsWith("claim:"));
  const firstClaimGas = claimTransactions.length ? Number(claimTransactions[0].gasUsed) : null;
  const subsequentClaimGas = claimTransactions.length > 1 ? Number(claimTransactions[1].gasUsed) : null;
  mergeState(scenarioDir, { claimedUsersExecuted: claimTransactions.length, firstClaimGas, subsequentClaimGas });
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      claimed: claimTransactions.length,
      firstClaimGas,
      subsequentClaimGas,
      avgClaimGas: claimTransactions.length
        ? Math.round(claimTransactions.reduce((sum, tx) => sum + Number(tx.gasUsed), 0) / claimTransactions.length)
        : 0,
    },
    transactions: txs,
    claimFundingTransactions,
  });
}

async function submitProof(scenarioDir, stepName) {
  const { state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const detail = await waitForReceiptWithMetrics(
    batch.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked)
  );
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { path: "1" },
    transactions: [summarizeReceipt(networkName, "submitProof", detail)],
  });
}

async function openDispute(scenarioDir, stepName) {
  const { state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const detail = await waitForReceiptWithMetrics(
    batch.dispute(disputeVectors.CT_P_withVsig_Locked_Future, disputeVectors.CT_V_withPsig_Unlocked_Future)
  );
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { disputeVector: "future" },
    transactions: [summarizeReceipt(networkName, "dispute", detail)],
  });
}

async function resolveValidDispute(scenarioDir, stepName) {
  const { state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const detail = await waitForReceiptWithMetrics(
    batch.resolveValidDispute(disputeVectors.CT_P_withVsig_Unlocked_Future)
  );
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { path: "1" },
    transactions: [summarizeReceipt(networkName, "resolveValidDispute", detail)],
  });
}

async function resolveInvalidDispute(scenarioDir, stepName) {
  const { state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const detail = await waitForReceiptWithMetrics(
    batch.resolveInvalidDispute(disputeVectors.revSecretP)
  );
  writeStepArtifact(scenarioDir, stepName, {
    highlights: { path: "4" },
    transactions: [summarizeReceipt(networkName, "resolveInvalidDispute", detail)],
  });
}

async function challengeLeaf(scenarioDir, stepName) {
  const { state, actors, networkName } = await getContext(scenarioDir);
  const ctx = getScenarioContext(scenarioDir);
  const merkle = readJson(ctx.merklePath, null);
  const invalidLeaf = merkle.leaves.find((leaf) => leaf.isInvalid);
  if (!invalidLeaf) throw new Error("No invalid leaf configured for this scenario");
  const batch = await getBatchContract(state.batchAddress, actors.verifier.signer);
  const detail = await waitForReceiptWithMetrics(
    batch.challengeLeaf(invalidLeaf.index, invalidLeaf.addr, invalidLeaf.amount, invalidLeaf.proof)
  );
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      challengedIndex: invalidLeaf.index,
      challengedAddr: invalidLeaf.addr,
      challengedAmount: invalidLeaf.amount,
    },
    transactions: [summarizeReceipt(networkName, "challengeLeaf", detail)],
  });
}

async function extendChallengeWindow(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.verifier.signer);
  const extensionFee = ethers.utils.parseEther("0.05");
  const balancesBefore = await captureBalances({
    verifier: actors.verifier.address,
    batch: state.batchAddress,
  });
  const detail = await waitForReceiptWithMetrics(
    batch.connect(actors.verifier.signer).extendChallengeWindow({ value: extensionFee })
  );
  const extensionEvent = (detail.receipt.events || []).find(
    (e) => e.event === "challengeWindowExtended"
  );
  const newExtensionCount = extensionEvent ? Number(extensionEvent.args[1]) : (Number(state.extensionCount || 0) + 1);
  mergeState(scenarioDir, { extensionCount: newExtensionCount });
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      extensionFeeEth: "0.05",
      burntTo: "0x000000000000000000000000000000000000dEaD",
      newDeadline: extensionEvent ? extensionEvent.args[0].toString() : null,
      extensionNumber: newExtensionCount,
    },
    balancesBefore,
    balancesAfter: await captureBalances({
      verifier: actors.verifier.address,
      batch: state.batchAddress,
    }),
    transactions: [summarizeReceipt(networkName, "extendChallengeWindow", detail)],
  });
}

async function settle(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const batch = await getBatchContract(state.batchAddress, actors.prover.signer);
  const balancesBefore = await captureBalances({
    prover: actors.prover.address,
    verifier: actors.verifier.address,
    batch: state.batchAddress,
  });
  const detail = await waitForReceiptWithMetrics(batch.settle());
  const balancesAfter = await captureBalances({
    prover: actors.prover.address,
    verifier: actors.verifier.address,
    batch: state.batchAddress,
  });
  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      path: config.path,
      stateEventCodes: (detail.receipt.events || [])
        .filter((event) => event.event === "stateEvent")
        .map((event) => ({ code: event.args[0], label: STATE_EVENT_CODES[event.args[0]] || "unknown" })),
    },
    balancesBefore,
    balancesAfter,
    transactions: [summarizeReceipt(networkName, "settle", detail)],
  });
}

// -- EIP-4844 blob helpers -----------------------------------------------------

let _kzg;
async function getKZG() {
  if (!_kzg) {
    const { loadKZG } = require("kzg-wasm");
    _kzg = await loadKZG();
  }
  return _kzg;
}

function buildBlobData(addrs, amounts, commitments = []) {
  const blob = new Uint8Array(131072); // 4096 field elements × 32 bytes
  let offset = 0;
  // A blob stores BLS12-381 scalar-field elements.  An arbitrary bytes32
  // commitment may exceed the field modulus, so encode it as two zero-padded
  // 16-byte halves; both halves are valid fields and retain all 32 bytes.
  const recordBytes = commitments.length ? 160 : 96;
  for (let i = 0; i < addrs.length && offset + recordBytes <= 131072; i++) {
    blob.set(ethers.utils.arrayify(ethers.utils.hexZeroPad(addrs[i], 32)), offset);
    offset += 32;
    blob.set(
      ethers.utils.arrayify(
        ethers.utils.hexZeroPad(ethers.BigNumber.from(amounts[i]).toHexString(), 32)
      ),
      offset
    );
    offset += 32;
    blob.set(
      ethers.utils.arrayify(
        ethers.utils.hexZeroPad(ethers.BigNumber.from(i).toHexString(), 32)
      ),
      offset
    );
    offset += 32;
    if (commitments.length) {
      const commitmentBytes = ethers.utils.arrayify(commitments[i]);
      blob.set(
        ethers.utils.arrayify(ethers.utils.hexZeroPad(ethers.utils.hexlify(commitmentBytes.slice(0, 16)), 32)),
        offset
      );
      offset += 32;
      blob.set(
        ethers.utils.arrayify(ethers.utils.hexZeroPad(ethers.utils.hexlify(commitmentBytes.slice(16, 32)), 32)),
        offset
      );
      offset += 32;
    }
  }
  return blob;
}

// -- submitRootBlob: EIP-712 leaves + EIP-4844 blob DA ------------------------

async function submitRootBlob(scenarioDir, stepName) {
  const { BlobEIP4844Transaction } = require("@ethereumjs/tx");
  const { Common } = require("@ethereumjs/common");
  const crypto = require("crypto");

  const { config, state, actors, networkName, provider } = await getContext(scenarioDir);
  const networkInfo = await provider.getNetwork();
  const chainId = networkInfo.chainId;

  const amount = ethers.utils.parseEther(config.leafAmountEth || "0.001");
  const batchSize = config.batchSize || 1;
  const isR2 = config.protocolVersion === "r2";
  const invalidLeaf = config.invalidLeaf || null;
  const sharerAddr =
    actors.users.length > 0 ? actors.users[0].address : actors.deployer.address;

  const addrs = [];
  const amounts = [];
  const commitments = [];
  const leafMeta = [];

  for (let i = 0; i < batchSize; i++) {
    let addr = sharerAddr;
    let leafAmt = amount;
    let isInvalid = false;
    if (invalidLeaf && i === invalidLeaf.index) {
      if (invalidLeaf.type === "zero-address") addr = ethers.constants.AddressZero;
      if (invalidLeaf.type === "zero-amount") leafAmt = ethers.constants.Zero;
      isInvalid = true;
    }
    addrs.push(addr);
    amounts.push(leafAmt);
    leafMeta.push({ isInvalid });
  }
  let root;
  let tree;
  let paddedBatchSize = batchSize;
  if (isR2) {
    if (invalidLeaf) throw new Error("R2 rejects invalid leaves during registration; use the dedicated negative-test operation");
    if (actors.users.length < batchSize) throw new Error("R2 submission requires one registered actor per real obligation");
    const registeredContract = await getBatchContract(state.batchAddress, actors.prover.signer);
    const registrations = await r2Registrations(config, actors, registeredContract);
    addrs.splice(0, addrs.length, ...registrations.map((entry) => entry.addr));
    amounts.splice(0, amounts.length, ...registrations.map((entry) => entry.amount));
    commitments.push(...registrations.map((entry) => entry.obligationCommitment));
    const r2Tree = buildRegistrationTree(chainId, state.batchAddress, registrations);
    root = r2Tree.root;
    tree = r2Tree.tree;
    paddedBatchSize = r2Tree.padded;
  } else {
    ({ root, tree } = buildMerkleTree712(chainId, state.batchAddress, addrs, amounts));
  }

  const kzg = await getKZG();
  const blob = buildBlobData(addrs, amounts, commitments);
  const commitment = kzg.blobToKzgCommitment(blob);
  const kzgProof = kzg.computeBlobKzgProof(blob, commitment);

  const sha256digest = crypto
    .createHash("sha256")
    .update(Buffer.from(commitment))
    .digest();
  sha256digest[0] = 0x01;
  const versionedHash = Uint8Array.from(sha256digest);

  const proverKey = actors.prover.privateKey;
  if (!proverKey) throw new Error("Prover private key required for blob transaction");

  const contract = await getBatchContract(state.batchAddress, actors.prover.signer);
  const proverWallet = new ethers.Wallet(proverKey);
  const nonce = await provider.getTransactionCount(proverWallet.address);
  const latestBlock = await provider.getBlock("latest");
  const baseFee = latestBlock.baseFeePerGas
    ? BigInt(latestBlock.baseFeePerGas.toString())
    : 1_000_000_000n;

  const calldata = contract.interface.encodeFunctionData("submitMerkleRoot", [root, paddedBatchSize]);

  const kzgWrapper = {
    blobToKzgCommitment: (b) => kzg.blobToKzgCommitment(b),
    computeBlobKzgProof: (b, c) => kzg.computeBlobKzgProof(b, c),
    verifyKzgProof: (c, z, y, p) => kzg.verifyKzgProof(c, z, y, p),
    verifyBlobKzgProofBatch: (bs, cs, ps) => kzg.verifyBlobKzgProofBatch(bs, cs, ps),
  };

  const common = Common.custom(
    { chainId, name: networkName, networkId: chainId },
    { hardfork: "cancun", customCrypto: { kzg: kzgWrapper } }
  );

  const blobTx = BlobEIP4844Transaction.fromTxData(
    {
      nonce: BigInt(nonce),
      maxFeePerGas: baseFee * 2n + 1_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      gasLimit: 3_000_000n,
      to: state.batchAddress.toLowerCase(),
      data: ethers.utils.arrayify(calldata),
      maxFeePerBlobGas: 1_000_000_000n,
      blobVersionedHashes: [versionedHash],
      blobs: [blob],
      kzgCommitments: [commitment],
      kzgProofs: [kzgProof],
    },
    { common }
  );

  const privKeyBuf = Buffer.from(proverKey.replace("0x", ""), "hex");
  const signedTx = blobTx.sign(privKeyBuf);
  const rawHex = "0x" + Buffer.from(signedTx.serializeNetworkWrapper()).toString("hex");

  const txHash = await provider.send("eth_sendRawTransaction", [rawHex]);

  // Mine on local Hardhat; poll on live networks
  try {
    await provider.send("evm_mine", []);
  } catch (_) {}

  let receipt = null;
  for (let i = 0; i < 60; i++) {
    receipt = await provider.getTransactionReceipt(txHash);
    if (receipt) break;
    await new Promise((r) => setTimeout(r, 3000));
  }
  if (!receipt) throw new Error(`Blob tx ${txHash} not mined after timeout`);

  const submitBlock = await provider.getBlock(receipt.blockNumber);
  const rawReceipt = await provider.send("eth_getTransactionReceipt", [txHash]);
  const blobGasUsed = ethers.BigNumber.from(rawReceipt.blobGasUsed || "0x0");
  const blobGasPrice = ethers.BigNumber.from(rawReceipt.blobGasPrice || "0x0");
  const effectiveGasPrice = receipt.effectiveGasPrice || ethers.constants.Zero;
  const executionFeeWei = receipt.gasUsed.mul(effectiveGasPrice);
  const blobFeeWei = blobGasUsed.mul(blobGasPrice);
  const leaves = addrs.map((addr, i) => ({
    index: i,
    addr,
    amount: amounts[i].toString(),
    obligationCommitment: commitments[i] || null,
    isInvalid: leafMeta[i].isInvalid,
    proof: isR2 ? proofFor(tree, i) : getMerkleProof712(tree, i),
  }));
  const merkleArtifact = { root, tree, leaves, submitBlockTimestamp: submitBlock.timestamp };
  const ctx = getScenarioContext(scenarioDir);
  writeJson(ctx.merklePath, serializable(merkleArtifact));

  mergeState(scenarioDir, {
    currentMerkleRoot: root,
    batchSize,
    paddedBatchSize,
    batchSubmitBlockTimestamp: submitBlock.timestamp,
    submitGas: receipt.gasUsed.toString(),
  });

  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      merkleRoot: root,
      batchSize,
      paddedBatchSize,
      gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: effectiveGasPrice.toString(),
      blobGasUsed: blobGasUsed.toString(),
      blobGasPrice: blobGasPrice.toString(),
      executionFeeWei: executionFeeWei.toString(),
      blobFeeWei: blobFeeWei.toString(),
      totalFeeWei: executionFeeWei.add(blobFeeWei).toString(),
      perUserGas: Math.round(Number(receipt.gasUsed) / batchSize),
      txHash,
      txLink: explorerLinks(networkName, txHash, "tx"),
    },
    transactions: [
      {
        label: "submitMerkleRoot(blob)",
        txHash,
        txLink: explorerLinks(networkName, txHash, "tx"),
        gasUsed: receipt.gasUsed.toString(),
        effectiveGasPrice: effectiveGasPrice.toString(),
        blobGasUsed: blobGasUsed.toString(),
        blobGasPrice: blobGasPrice.toString(),
        executionFeeWei: executionFeeWei.toString(),
        blobFeeWei: blobFeeWei.toString(),
        totalFeeWei: executionFeeWei.add(blobFeeWei).toString(),
        blockNumber: receipt.blockNumber,
        blockTimestamp: submitBlock.timestamp,
      },
    ],
  });
}

// -- sparseClaims: claim claimFraction (or claimCount) of the batch ------------

async function sparseClaims(scenarioDir, stepName) {
  const { config, state, actors, networkName } = await getContext(scenarioDir);
  const ctx = getScenarioContext(scenarioDir);
  const merkle = readJson(ctx.merklePath, null);
  if (!merkle) throw new Error("Missing merkle artifact; run submitRootBlob first");

  const batchSize = Number(state.batchSize || merkle.leaves.length);
  const numClaims =
    config.claimCount !== undefined
      ? config.claimCount
      : Math.max(1, Math.round((config.claimFraction !== undefined ? config.claimFraction : 1.0) * batchSize));

  const claimerActor = actors.users.length > 0 ? actors.users[0] : actors.deployer;
  const batch = await getBatchContract(state.batchAddress, claimerActor.signer);

  // Top up claimer for gas if needed
  if (config.claimFundingEth) {
    const target = ethers.utils.parseEther(config.claimFundingEth);
    const topUp = await ensureFunded(actors.deployer.signer, claimerActor.signer, target);
    if (topUp) await (await Promise.resolve(topUp)).wait();
  }

  const txResults = [];
  let coldGas = 0;
  let warmGas = 0;
  let claimed = 0;

  for (let i = 0; i < numClaims && i < merkle.leaves.length; i++) {
    const leaf = merkle.leaves[i];
    if (!leaf || leaf.isInvalid) continue;

    const alreadyClaimed = await batch.isClaimed(leaf.index);
    if (alreadyClaimed) continue;

    const startedAt = Date.now();
    const tx = await batch.claimWithMerkleProof(
      leaf.addr,
      leaf.amount,
      leaf.proof,
      leaf.index,
      { gasLimit: 200000 }
    );
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);
    const gasUsed = receipt.gasUsed.toNumber();

    if (claimed === 0) coldGas = gasUsed;
    if (claimed === 1) warmGas = gasUsed;
    claimed++;

    txResults.push({
      label: `claim:${leaf.index}`,
      txHash: tx.hash,
      txLink: explorerLinks(networkName, tx.hash, "tx"),
      from: tx.from,
      to: tx.to,
      gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: bnToString(receipt.effectiveGasPrice || 0),
      gasCostWei: bnToString(
        (receipt.effectiveGasPrice || ethers.constants.Zero).mul(receipt.gasUsed)
      ),
      blockNumber: receipt.blockNumber,
      blockTimestamp: block.timestamp,
      latencyMs: Date.now() - startedAt,
      status: receipt.status,
    });
  }

  if (claimed === 1) warmGas = coldGas;

  const submitGas = Number(state.submitGas || 0);
  const cEff = claimed > 0 ? Math.round(submitGas / claimed + warmGas) : 0;
  const albaBaseline = 253566;
  const savings = cEff > 0 ? ((1 - cEff / albaBaseline) * 100).toFixed(1) + "%" : "n/a";

  mergeState(scenarioDir, {
    claimedCount: claimed,
    coldClaimGas: coldGas,
    warmClaimGas: warmGas,
    cEff,
  });

  writeStepArtifact(scenarioDir, stepName, {
    highlights: {
      claimFraction: config.claimFraction,
      claimCount: config.claimCount,
      claimedCount: claimed,
      coldClaimGas: coldGas,
      warmClaimGas: warmGas,
      cEff,
      savingsVsAlba: savings,
      avgClaimGas:
        claimed > 0
          ? Math.round(txResults.reduce((s, t) => s + Number(t.gasUsed), 0) / claimed)
          : 0,
    },
    transactions: txResults,
  });
}

const operations = {
  deploySharedInfra,
  deployBatch,
  fundAndSetup,
  lockOnly: (scenarioDir, stepName) => fundAndSetup(scenarioDir, stepName, { skipSetup: true }),
  registerUsers,
  depositUserPool,
  validateR2PreSubmit,
  validateR2PostSubmit,
  waitForClaimPhase: (scenarioDir, stepName) => waitCheckpoint(scenarioDir, stepName, "claim"),
  waitForZeroClaimSettle: (scenarioDir, stepName) => waitCheckpoint(scenarioDir, stepName, "zero-claim-settle"),
  claimUsers,
  submitProof,
  openDispute,
  resolveValidDispute,
  resolveInvalidDispute,
  challengeLeaf,
  extendChallengeWindow,
  settle,
  submitRootBlob,
  sparseClaims,
  waitForSettlePhase: (scenarioDir, stepName) => waitCheckpoint(scenarioDir, stepName, "zero-claim-settle"),
};

module.exports = operations;

