const path = require("path");
const { ethers } = require("hardhat");
const { loadConfig, loadState } = require("../../lib/scenario");
const { loadOrCreateActors } = require("../../lib/actors");

async function main() {
  const scenarioId = process.argv[2] || "b6_sparse_n256_f50";
  const scenarioDir = path.join(__dirname, "scenarios", scenarioId);
  const config = loadConfig(scenarioDir);
  const state = loadState(scenarioDir);
  const actors = await loadOrCreateActors(scenarioDir, config, ethers.provider);
  const batch = await ethers.getContractAt("AuroraFullTestnet", state.batchAddress, actors.deployer.signer);
  const registeredCount = await batch.registeredCount();
  const unregisteredActors = [];
  for (const user of actors.users) {
    if ((await batch.registrationIndexPlusOne(user.address)).isZero()) unregisteredActors.push(user);
  }
  const rows = [];
  for (const user of unregisteredActors) {
    const [latest, pending] = await Promise.all([
      ethers.provider.getTransactionCount(user.address, "latest"),
      ethers.provider.getTransactionCount(user.address, "pending"),
    ]);
    rows.push({ address: user.address, latest, pending, pendingGap: pending - latest });
  }
  console.log(JSON.stringify({
    scenarioId,
    batchAddress: state.batchAddress,
    registeredCount: registeredCount.toString(),
    unregistered: unregisteredActors.length,
    pendingUsers: rows.filter((row) => row.pendingGap > 0),
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
