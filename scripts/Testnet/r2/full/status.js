const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");
const { ROOT, rootScenarios } = require("./matrix");

const ABI = [
  "function batchSubmitTime() view returns(uint256)",
  "function currentMerkleRoot() view returns(bytes32)",
  "function claimedCount() view returns(uint256)",
  "function registeredCount() view returns(uint256)",
];

async function main() {
  const latest = await ethers.provider.getBlock("latest");
  const rows = [];
  for (const config of rootScenarios) {
    const statePath = path.join(ROOT, config.scenarioId, "artifacts", "state.json");
    const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
    const batch = new ethers.Contract(state.batchAddress, ABI, ethers.provider);
    const [submittedAt, root, claimedCount, registeredCount] = await Promise.all([
      batch.batchSubmitTime(), batch.currentMerkleRoot(), batch.claimedCount(), batch.registeredCount(),
    ]);
    const claimOpenAt = submittedAt.toNumber() + 24 * 60 * 60;
    rows.push({
      scenarioId: config.scenarioId,
      batchAddress: state.batchAddress,
      registeredCount: registeredCount.toString(),
      claimedCount: claimedCount.toString(),
      submittedAt: submittedAt.toString(),
      claimOpenAt,
      claimOpen: latest.timestamp > claimOpenAt,
      rootAccepted: root !== ethers.constants.HashZero,
    });
  }
  console.log(JSON.stringify({
    latestBlock: latest.number,
    latestTimestamp: latest.timestamp,
    rootScenarioCount: rows.length,
    claimOpenCount: rows.filter((row) => row.claimOpen).length,
    rootsAccepted: rows.filter((row) => row.rootAccepted).length,
    scenarios: rows,
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
