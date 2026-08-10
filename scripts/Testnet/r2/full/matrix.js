const path = require("path");

const ROOT = path.join(__dirname, "scenarios");
const COMMON = {
  protocolVersion: "r2",
  sharedDeploymentKey: "aurora-r2",
  sharedActorPool: "r2-full",
  sharedActorPoolSize: 256,
  leafAmountEth: "0.0001",
  proverFundingEth: "0.02",
  verifierFundingEth: "0.02",
  userFundingEth: "0.003",
  gasBufferEth: "0.002",
  sharedUserMinimumEth: "0.001",
  txParallelism: 24,
};

function poolFor(n) {
  return (n / 10_000).toFixed(4);
}

function rootScenario(id, group, n, claimCount) {
  return {
    scenarioId: id,
    description: `${group}: canonical R2 lifecycle at n=${n}`,
    ...COMMON,
    batchSize: n,
    userCount: n,
    depositUserPoolEth: poolFor(n),
    claimCount,
    path: claimCount > 0 ? "path2" : "path2b",
  };
}

function directScenario(id, pathName) {
  return {
    scenarioId: id,
    description: `B4: ${pathName} settlement path`,
    ...COMMON,
    batchSize: 0,
    userCount: 0,
    path: pathName,
  };
}

const rootScenarios = [
  ...[1, 16, 64, 128].map((n) => rootScenario(`b1_submit_n${String(n).padStart(3, "0")}`, "B1 submit-root", n, 1)),
  ...[1, 16, 64, 128].map((n) => rootScenario(`b2_lifecycle_n${String(n).padStart(3, "0")}`, "B2 amortized lifecycle", n, n)),
  rootScenario("b3_rejection_successor", "B3 rejection successor", 1, 1),
  rootScenario("b4_path2b", "B4 Path 2b", 1, 0),
  ...[
    ["10", 13], ["25", 32], ["50", 64], ["75", 96], ["100", 128],
  ].map(([fraction, claimCount]) => rootScenario(`b5_sparse_n128_f${fraction}`, "B5 sparse lifecycle", 128, claimCount)),
  ...[
    [16, 8], [64, 32], [128, 64], [256, 128],
  ].map(([n, claimCount]) => rootScenario(`b6_sparse_n${String(n).padStart(3, "0")}_f50`, "B6 sparse lifecycle", n, claimCount)),
];

const directScenarios = [
  { config: directScenario("b4_path1", "path1"), steps: [["02_fund_setup", "fundAndSetup"], ["03_submit_proof", "submitProof"], ["04_settle", "settle"]] },
  { config: directScenario("b4_path1b", "path1b"), steps: [["02_fund_setup", "fundAndSetup"], ["03_open_dispute", "openDispute"], ["04_resolve_valid", "resolveValidDispute"], ["05_settle", "settle"]] },
  { config: directScenario("b4_path3", "path3"), steps: [["02_fund_setup", "fundAndSetup"], ["03_open_dispute", "openDispute"], ["04_settle_freeze", "settle"]] },
  { config: directScenario("b4_path4", "path4"), steps: [["02_fund_setup", "fundAndSetup"], ["03_open_dispute", "openDispute"], ["04_resolve_invalid", "resolveInvalidDispute"], ["05_settle", "settle"]] },
  { config: directScenario("b4_path5", "path5"), steps: [["02_lock_only", "lockOnly"], ["03_settle", "settle"]] },
];

function scenarioDirectory(id) {
  return path.join(ROOT, id);
}

module.exports = { ROOT, rootScenarios, directScenarios, scenarioDirectory };
