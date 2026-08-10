const fs = require("fs");
const path = require("path");
const operations = require("../../lib/operations");
const { readJson, writeJson } = require("../../lib/scenario");
const { ROOT, rootScenarios, scenarioDirectory } = require("./matrix");

async function main() {
  const rows = [];
  for (const config of rootScenarios) {
    const directory = scenarioDirectory(config.scenarioId);
    const checkpointPath = path.join(directory, "artifacts", "10_wait_settlement.json");
    if (!fs.existsSync(checkpointPath)) {
      await operations.waitForZeroClaimSettle(directory, "10_wait_settlement");
    }
    const checkpoint = readJson(checkpointPath, {});
    rows.push({ scenarioId: config.scenarioId, ...checkpoint.highlights });
  }
  const targets = rows.map((row) => row.targetTimestamp).filter(Boolean);
  const report = {
    recordedAt: new Date().toISOString(),
    rootScenarioCount: rows.length,
    earliestSettlementTimestamp: Math.min(...targets),
    latestSettlementTimestamp: Math.max(...targets),
    scenarios: rows,
  };
  writeJson(path.join(ROOT, "settlement-wait-checkpoint.json"), report);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
