const { ethers } = require("hardhat");
const EthCrypto = require("eth-crypto");
const { getScenarioContext, readJson, writeJson } = require("./scenario");

const HARDHAT_MNEMONIC = "test test test test test test test test test test test junk";

function normalizePrivateKeys(rawValue) {
  if (!rawValue) return [];
  return rawValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function walletRecord(wallet, source, includePrivateKey) {
  return {
    address: wallet.address,
    source,
    privateKey: includePrivateKey ? wallet.privateKey : undefined,
  };
}

function createGeneratedWallet(provider) {
  return ethers.Wallet.createRandom().connect(provider);
}

function toSerializableActors(actorState) {
  return JSON.parse(JSON.stringify(actorState));
}

function sharedActorPoolPath(networkName, poolKey) {
  return require("path").join(__dirname, "..", "shared", `${networkName}-${poolKey}-actors.generated.json`);
}

function publicActorRecord(record) {
  return {
    address: record.address,
    source: record.source,
  };
}

async function loadOrCreateActors(scenarioDir, config, provider) {
  const ctx = getScenarioContext(scenarioDir);
  const persisted = readJson(ctx.actorsPath, null);
  const signers = await ethers.getSigners();
  const [deployer] = signers;
  const network = await provider.getNetwork();
  const isLocalNetwork = network.name === "localhost" || network.name === "hardhat" || String(network.chainId) === "31337";

  if (isLocalNetwork) {
    const userCount = config.userCount !== undefined ? config.userCount : (config.batchSize || 0);
    const derive = (index) => ethers.Wallet.fromMnemonic(HARDHAT_MNEMONIC, `m/44'/60'/0'/0/${index}`).connect(provider);
    const entropyP = Buffer.from("ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao", "utf-8");
    const entropyV = Buffer.from("ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo", "utf-8");
    const identityP = EthCrypto.createIdentity(entropyP);
    const identityV = EthCrypto.createIdentity(entropyV);
    const proverSigner = new ethers.Wallet(identityP.privateKey, provider);
    const verifierSigner = new ethers.Wallet(identityV.privateKey, provider);
    return {
      deployer: { address: derive(0).address, source: "hardhat-wallet", signer: derive(0), privateKey: derive(0).privateKey },
      prover: { address: proverSigner.address, source: "fixture-wallet", signer: proverSigner, privateKey: proverSigner.privateKey },
      verifier: { address: verifierSigner.address, source: "fixture-wallet", signer: verifierSigner, privateKey: verifierSigner.privateKey },
      users: Array.from({ length: userCount }, (_, index) => {
        const signer = derive(index + 2);
        return { address: signer.address, source: "hardhat-wallet", signer, privateKey: signer.privateKey };
      }),
    };
  }

  const sharedPoolKey = config.sharedActorPool || "";
  if (sharedPoolKey) {
    const userCount = config.userCount !== undefined ? config.userCount : (config.batchSize || 0);
    const poolSize = config.sharedActorPoolSize || 256;
    if (userCount > poolSize) {
      throw new Error(`Scenario requires ${userCount} users but shared actor pool ${sharedPoolKey} has size ${poolSize}`);
    }
    const poolPath = sharedActorPoolPath(network.name, sharedPoolKey);
    let sharedState = readJson(poolPath, null);
    if (!sharedState) {
      const proverKey = process.env.TESTNET_PROVER_PRIVATE_KEY || "";
      const deployerKey = process.env.SEPOLIA_PRIVATE_KEY || "";
      const verifierKey = process.env.TESTNET_VERIFIER_PRIVATE_KEY || "";
      const userKeys = normalizePrivateKeys(process.env.TESTNET_USER_PRIVATE_KEYS || "");
      sharedState = {
        deployer: { address: deployer.address, source: "hardhat-signer" },
        prover: proverKey
          ? walletRecord(new ethers.Wallet(proverKey), "env", true)
          : deployerKey
            ? walletRecord(new ethers.Wallet(deployerKey), "env", true)
            : { address: deployer.address, source: "hardhat-signer" },
        verifier: verifierKey
          ? walletRecord(new ethers.Wallet(verifierKey), "env", true)
          : walletRecord(createGeneratedWallet(provider), "generated", true),
        users: Array.from({ length: poolSize }, (_, index) => userKeys[index]
          ? walletRecord(new ethers.Wallet(userKeys[index]), "env", true)
          : walletRecord(createGeneratedWallet(provider), "generated", true)),
      };
      writeJson(poolPath, toSerializableActors(sharedState));
    }
    if ((sharedState.users || []).length < userCount) {
      throw new Error(`Shared actor pool ${sharedPoolKey} contains only ${(sharedState.users || []).length} users`);
    }
    const scenarioState = {
      deployer: publicActorRecord(sharedState.deployer),
      prover: publicActorRecord(sharedState.prover),
      verifier: publicActorRecord(sharedState.verifier),
      users: sharedState.users.slice(0, userCount).map(publicActorRecord),
      sharedActorPool: sharedPoolKey,
      sharedActorPoolSize: sharedState.users.length,
    };
    writeJson(ctx.actorsPath, scenarioState);
    return materializeActors({ ...sharedState, users: sharedState.users.slice(0, userCount) }, provider, deployer);
  }

  if (persisted) {
    return materializeActors(persisted, provider, deployer);
  }

  const proverKey = process.env.TESTNET_PROVER_PRIVATE_KEY || "";
  const deployerKey = process.env.SEPOLIA_PRIVATE_KEY || "";
  const verifierKey = process.env.TESTNET_VERIFIER_PRIVATE_KEY || "";
  const userKeys = normalizePrivateKeys(process.env.TESTNET_USER_PRIVATE_KEYS || "");
  const userCount = config.userCount !== undefined ? config.userCount : (config.batchSize || 0);

  const actorState = {
    deployer: { address: deployer.address, source: "hardhat-signer" },
    prover: proverKey
      ? walletRecord(new ethers.Wallet(proverKey), "env", true)
      : deployerKey
        ? walletRecord(new ethers.Wallet(deployerKey), "env", true)
        : { address: deployer.address, source: "hardhat-signer" },
    verifier: verifierKey
      ? walletRecord(new ethers.Wallet(verifierKey), "env", true)
      : walletRecord(createGeneratedWallet(provider), "generated", true),
    users: [],
  };

  for (let i = 0; i < userCount; i++) {
    if (userKeys[i]) {
      actorState.users.push(walletRecord(new ethers.Wallet(userKeys[i]), "env", true));
    } else {
      actorState.users.push(walletRecord(createGeneratedWallet(provider), "generated", true));
    }
  }

  writeJson(ctx.actorsPath, toSerializableActors(actorState));
  return materializeActors(actorState, provider, deployer);
}

function materializeRecord(record, provider, deployer) {
  if (!record) return null;
  if (record.privateKey) {
    return { ...record, signer: new ethers.Wallet(record.privateKey, provider) };
  }
  if (record.address.toLowerCase() === deployer.address.toLowerCase()) {
    return { ...record, signer: deployer };
  }
  return { ...record, signer: deployer };
}

function materializeActors(actorState, provider, deployer) {
  const actors = {
    deployer: { ...actorState.deployer, signer: deployer },
    prover: materializeRecord(actorState.prover, provider, deployer),
    verifier: materializeRecord(actorState.verifier, provider, deployer),
    users: (actorState.users || []).map((entry) => materializeRecord(entry, provider, deployer)),
  };
  return actors;
}

async function ensureFunded(funderSigner, targetSigner, targetBalanceWei) {
  if (funderSigner.address && targetSigner.address &&
      funderSigner.address.toLowerCase() === targetSigner.address.toLowerCase()) return null;
  const currentBalance = await targetSigner.getBalance();
  if (currentBalance.gte(targetBalanceWei)) {
    return null;
  }
  const topUpValue = targetBalanceWei.sub(currentBalance);
  return funderSigner.sendTransaction({ to: targetSigner.address, value: topUpValue });
}

module.exports = {
  loadOrCreateActors,
  ensureFunded,
};
