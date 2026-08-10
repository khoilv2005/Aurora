const fs = require("fs");
const path = require("path");
const { ROOT, rootScenarios } = require("./matrix");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function artifact(id, step) {
  const relativePath = path.join("scripts", "Testnet", "r2", "full", "scenarios", id, "artifacts", `${step}.json`);
  return { relativePath: relativePath.replace(/\\/g, "/"), data: readJson(path.join(ROOT, id, "artifacts", `${step}.json`)) };
}

function gas(transaction) {
  return Number(transaction.gasUsed);
}

function transaction(data, label) {
  const result = (data.transactions || []).find((entry) => entry.label === label);
  if (!result) throw new Error(`Missing ${label}`);
  return result;
}

function mean(values) {
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}

function scenarioProtocolGas(id, steps) {
  let total = 0;
  const sources = [];
  for (const step of steps) {
    const entry = artifact(id, step);
    const values = (entry.data.transactions || []).map(gas);
    total += values.reduce((sum, value) => sum + value, 0);
    sources.push(entry.relativePath);
  }
  return { gas: total, sources };
}

function rootRow(id) {
  const submit = artifact(id, "06_submit_root");
  const registration = artifact(id, "03_register");
  const config = readJson(path.join(ROOT, id, "scenario.json"));
  return {
    scenarioId: id,
    n: config.batchSize,
    paddedN: submit.data.highlights.paddedBatchSize,
    registrationAverageGas: registration.data.highlights.avgRegisterGas,
    registrationCount: registration.data.highlights.registeredUsers,
    rootSubmissionGas: Number(submit.data.highlights.gasUsed),
    rootExecutionFeeWei: submit.data.highlights.executionFeeWei,
    blobFeeWei: submit.data.highlights.blobFeeWei,
    sources: [registration.relativePath, submit.relativePath],
  };
}

function claimRow(id) {
  const claim = artifact(id, "09_claim");
  const settle = artifact(id, "11_settle");
  const submit = artifact(id, "06_submit_root");
  const config = readJson(path.join(ROOT, id, "scenario.json"));
  const claimCount = claim.data.highlights.claimed;
  const rootSubmissionGas = Number(submit.data.highlights.gasUsed);
  return {
    scenarioId: id,
    n: config.batchSize,
    rootSubmissionGas,
    claimCount,
    firstClaimGas: claim.data.highlights.firstClaimGas,
    subsequentClaimGas: claim.data.highlights.subsequentClaimGas,
    averageClaimGas: claim.data.highlights.avgClaimGas,
    effectiveClaimantGas: claimCount
      ? Math.round(rootSubmissionGas / claimCount + claim.data.highlights.avgClaimGas)
      : null,
    settlementGas: gas(transaction(settle.data, "settle")),
    settlementEvent: settle.data.highlights.stateEventCodes.map((entry) => entry.code),
    sources: [submit.relativePath, claim.relativePath, settle.relativePath],
  };
}

function directRow(id) {
  const dir = path.join(ROOT, id, "artifacts");
  const files = fs.readdirSync(dir).filter((file) => /^0\d_.*\.json$/.test(file)).sort();
  const transactions = files.flatMap((file) => readJson(path.join(dir, file)).transactions || []);
  return {
    scenarioId: id,
    totalGas: transactions.map(gas).reduce((sum, value) => sum + value, 0),
    operations: Object.fromEntries(transactions.map((entry) => [entry.label, gas(entry)])),
    sources: files.map((file) => path.join("scripts", "Testnet", "r2", "full", "scenarios", id, "artifacts", file).replace(/\\/g, "/")),
  };
}

function main() {
  const b1 = ["001", "016", "064", "128"].map((n) => rootRow(`b1_submit_n${n}`));
  const rootScalability = [...b1, rootRow("b6_sparse_n256_f50")];
  const b2 = ["001", "016", "064", "128"].map((n) => claimRow(`b2_lifecycle_n${n}`));
  const b5 = ["10", "25", "50", "75", "100"].map((fraction) => claimRow(`b5_sparse_n128_f${fraction}`));
  const b6 = ["016", "064", "128", "256"].map((n) => claimRow(`b6_sparse_n${n}_f50`));
  const direct = ["path1", "path1b", "path3", "path4", "path5"].map((name) => directRow(`b4_${name}`));
  const allClaims = [...b2, ...b5, ...b6, claimRow("b1_submit_n001"), claimRow("b1_submit_n016"), claimRow("b1_submit_n064"), claimRow("b1_submit_n128"), claimRow("b3_rejection_successor")];
  const ledgerPath = path.join(ROOT, "gas-ledger-final.json");
  const ledger = readJson(ledgerPath);
  const output = {
    generatedAt: new Date().toISOString(),
    metricDefinition: "All values are Sepolia transaction gasUsed. ETH-denominated fees are preserved only as raw artifact fields and are not used for gas comparisons.",
    completion: {
      rootScenarioCount: rootScenarios.length,
      claimedObligations: allClaims.reduce((sum, row) => sum + row.claimCount, 0),
      path2Settlements: allClaims.length + 1,
      directPathCount: direct.length,
      finalTransactionCount: ledger.totals.transactionCount,
      revertedTransactionCount: ledger.totals.revertedTransactions,
      finalLedgerSource: "scripts/Testnet/r2/full/scenarios/gas-ledger-final.json",
    },
    rootSubmission: rootScalability,
    lifecycle: {
      b2,
      sparseFraction: b5,
      sparseBatchSize: b6,
      meanClaimGasAcrossCompletedClaims: mean(allClaims.flatMap((row) => Array(row.claimCount).fill(row.averageClaimGas))),
    },
    directPaths: direct,
    representativeProtocolLifecycles: {
      b2n128: scenarioProtocolGas("b2_lifecycle_n128", ["01_deploy", "02_fund_setup", "03_register", "04_deposit_pool", "06_submit_root", "09_claim", "11_settle"]),
      b6n256f50: scenarioProtocolGas("b6_sparse_n256_f50", ["01_deploy", "02_fund_setup", "03_register", "04_deposit_pool", "06_submit_root", "09_claim", "11_settle"]),
    },
  };
  const outputPath = path.join(ROOT, "final-r2-metrics.json");
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
  console.log(JSON.stringify({ outputPath: outputPath.replace(/\\/g, "/"), completion: output.completion }, null, 2));
}

main();
