const fs = require("fs");
const path = require("path");
const operations = require("../../lib/operations");
const { ROOT, rootScenarios, scenarioDirectory } = require("./matrix");

async function main() {
  const selected = process.env.R2_SETTLE_SCENARIO || null;
  const scenarios = rootScenarios.filter((config) => !selected || config.scenarioId === selected);
  if (selected && scenarios.length !== 1) throw new Error(`Unknown scenario: ${selected}`);
  const report = [];
  for (const config of scenarios) {
    const directory = scenarioDirectory(config.scenarioId);
    const artifact = path.join(directory, "artifacts", "11_settle.json");
    if (fs.existsSync(artifact)) {
      report.push({ scenarioId: config.scenarioId, skipped: true });
      continue;
    }
    console.log(`[full-r2] ${config.scenarioId} :: 11_settle`);
    await operations.settle(directory, "11_settle");
    report.push({ scenarioId: config.scenarioId, skipped: false });
  }
  console.log(JSON.stringify({ completedAt: new Date().toISOString(), scenarios: report }, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
