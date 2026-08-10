const fs = require("fs");
const path = require("path");
const operations = require("../../lib/operations");
const { ensureDir, readJson, writeJson } = require("../../lib/scenario");
const { ROOT, rootScenarios, directScenarios, scenarioDirectory } = require("./matrix");

function artifactPath(scenarioDir, step) {
  return path.join(scenarioDir, "artifacts", `${step}.json`);
}

function ensureScenario(config) {
  const directory = scenarioDirectory(config.scenarioId);
  ensureDir(directory);
  const configPath = path.join(directory, "scenario.json");
  const existing = readJson(configPath, null);
  if (existing && JSON.stringify(existing) !== JSON.stringify(config)) {
    throw new Error(`Scenario configuration drift: ${config.scenarioId}`);
  }
  if (!existing) writeJson(configPath, config);
  return directory;
}

async function runIfMissing(scenarioDir, step, operationName) {
  if (fs.existsSync(artifactPath(scenarioDir, step))) return { step, operationName, skipped: true };
  const operation = operations[operationName];
  if (!operation) throw new Error(`Unknown operation ${operationName}`);
  console.log(`[full-r2] ${path.basename(scenarioDir)} :: ${step} (${operationName})`);
  await operation(scenarioDir, step);
  return { step, operationName, skipped: false };
}

async function launchRoot(config) {
  const directory = ensureScenario(config);
  const steps = [
    ["01_deploy", "deployBatch"],
    ["02_fund_setup", "fundAndSetup"],
    ["03_register", "registerUsers"],
    ["04_deposit_pool", "depositUserPool"],
    ["05_validate_pre_submit", "validateR2PreSubmit"],
    ["06_submit_root", "submitRootBlob"],
    ["07_validate_post_submit", "validateR2PostSubmit"],
  ];
  const results = [];
  for (const [step, operation] of steps) results.push(await runIfMissing(directory, step, operation));
  return { scenarioId: config.scenarioId, directory, results };
}

async function launchDirect(spec) {
  const directory = ensureScenario(spec.config);
  const results = [await runIfMissing(directory, "01_deploy", "deployBatch")];
  for (const [step, operation] of spec.steps) results.push(await runIfMissing(directory, step, operation));
  return { scenarioId: spec.config.scenarioId, directory, results };
}

async function main() {
  ensureDir(ROOT);
  const report = { startedAt: new Date().toISOString(), roots: [], direct: [] };
  // Fund the entire 256-EOA cohort once at the first n=256 scenario.
  const rootOrder = [...rootScenarios].sort((a, b) => b.batchSize - a.batchSize);
  for (const config of rootOrder) report.roots.push(await launchRoot(config));
  for (const spec of directScenarios) report.direct.push(await launchDirect(spec));
  report.completedAt = new Date().toISOString();
  writeJson(path.join(ROOT, "launch-report.json"), report);
  console.log(`[full-r2] launched ${report.roots.length} root scenarios and ${report.direct.length} direct-path scenarios`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
