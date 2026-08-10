const fs = require("fs");
const path = require("path");
const operations = require("../../lib/operations");
const { readJson, writeJson } = require("../../lib/scenario");
const { ROOT, rootScenarios, scenarioDirectory } = require("./matrix");

async function main() {
  const rows = [];
  for (const config of rootScenarios) {
    const directory = scenarioDirectory(config.scenarioId);
    const checkpointPath = path.join(directory, "artifacts", "08_wait_claim_phase.json");
    if (!fs.existsSync(checkpointPath)) {
      await operations.waitForClaimPhase(directory, "08_wait_claim_phase");
    }
    const checkpoint = readJson(checkpointPath, {});
    rows.push({ scenarioId: config.scenarioId, ...checkpoint.highlights });
  }
  const targets = rows.map((row) => row.targetTimestamp).filter(Boolean);
  const report = {
    recordedAt: new Date().toISOString(),
    rootScenarioCount: rows.length,
    earliestClaimTimestamp: Math.min(...targets),
    latestClaimTimestamp: Math.max(...targets),
    scenarios: rows,
  };
  writeJson(path.join(ROOT, "claim-wait-checkpoint.json"), report);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
