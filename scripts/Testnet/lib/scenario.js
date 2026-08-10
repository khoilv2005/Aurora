const fs = require("fs");
const path = require("path");
const { EXPLORER_BY_NETWORK } = require("./constants");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath, fallback = null) {
  if (!fs.existsSync(filePath)) {
    return fallback;
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, data) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf8");
}

function getScenarioContext(scenarioDir) {
  const artifactsDir = path.join(scenarioDir, "artifacts");
  ensureDir(artifactsDir);
  return {
    scenarioDir,
    artifactsDir,
    configPath: path.join(scenarioDir, "scenario.json"),
    statePath: path.join(artifactsDir, "state.json"),
    summaryPath: path.join(artifactsDir, "summary.json"),
    actorsPath: path.join(artifactsDir, "actors.generated.json"),
    merklePath: path.join(artifactsDir, "merkle.json"),
  };
}

function getSharedDeploymentPath(networkName, deploymentKey = "default") {
  return path.join(__dirname, "..", "shared", `${networkName}-${deploymentKey}.json`);
}

function loadConfig(scenarioDir) {
  const ctx = getScenarioContext(scenarioDir);
  return readJson(ctx.configPath, {});
}

function loadState(scenarioDir) {
  const ctx = getScenarioContext(scenarioDir);
  return readJson(ctx.statePath, {});
}

function saveState(scenarioDir, nextState) {
  const ctx = getScenarioContext(scenarioDir);
  writeJson(ctx.statePath, nextState);
}

function mergeState(scenarioDir, patch) {
  const state = loadState(scenarioDir);
  const next = { ...state, ...patch };
  saveState(scenarioDir, next);
  return next;
}

function explorerLinks(networkName, addressOrHash, kind) {
  const base = EXPLORER_BY_NETWORK[networkName] || "";
  if (!base) return null;
  if (kind === "address") return `${base}/address/${addressOrHash}`;
  if (kind === "tx") return `${base}/tx/${addressOrHash}`;
  return null;
}

function appendSummaryStep(scenarioDir, stepRecord) {
  const ctx = getScenarioContext(scenarioDir);
  const summary = readJson(ctx.summaryPath, { steps: [] });
  summary.steps.push(stepRecord);
  writeJson(ctx.summaryPath, summary);
}

function writeStepArtifact(scenarioDir, stepName, payload) {
  const ctx = getScenarioContext(scenarioDir);
  const artifactPath = path.join(ctx.artifactsDir, `${stepName}.json`);
  writeJson(artifactPath, payload);
  appendSummaryStep(scenarioDir, {
    step: stepName,
    recordedAt: new Date().toISOString(),
    artifact: artifactPath,
    highlights: payload.highlights || {},
  });
}

module.exports = {
  ensureDir,
  readJson,
  writeJson,
  getScenarioContext,
  getSharedDeploymentPath,
  loadConfig,
  loadState,
  saveState,
  mergeState,
  explorerLinks,
  writeStepArtifact,
};
