const fs = require("fs");
const path = require("path");
const { writeJson } = require("../../lib/scenario");
const { ROOT } = require("./matrix");

function filesRecursively(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    return entry.isDirectory() ? filesRecursively(fullPath) : [fullPath];
  });
}

function collectTransactions(payload) {
  const transactions = [];
  if (Array.isArray(payload.transactions)) transactions.push(...payload.transactions);
  if (Array.isArray(payload.registrationFundingTransactions)) transactions.push(...payload.registrationFundingTransactions);
  if (Array.isArray(payload.claimFundingTransactions)) transactions.push(...payload.claimFundingTransactions);
  if (payload.transaction) transactions.push(payload.transaction);
  return transactions.filter((transaction) => transaction && transaction.txHash);
}

function wei(value) {
  return BigInt(value || "0");
}

function main() {
  const outputFile = process.env.R2_GAS_LEDGER_FILE || "gas-ledger-through-claims.json";
  const fullArtifactRoot = path.join(ROOT);
  const sharedArtifactRoot = path.resolve(__dirname, "..", "00_shared", "artifacts");
  const artifactFiles = [
    ...filesRecursively(fullArtifactRoot),
    ...filesRecursively(sharedArtifactRoot),
  ].filter((file) => file.endsWith(".json") && !file.includes("gas-ledger-"));

  const unique = new Map();
  for (const file of artifactFiles) {
    let payload;
    try { payload = JSON.parse(fs.readFileSync(file, "utf8")); } catch (_) { continue; }
    for (const transaction of collectTransactions(payload)) {
      if (unique.has(transaction.txHash)) continue;
      const totalFeeWei = transaction.totalFeeWei || transaction.gasCostWei || transaction.executionFeeWei || "0";
      unique.set(transaction.txHash, {
        ...transaction,
        sourceArtifact: path.relative(path.resolve(__dirname, ".."), file).replace(/\\/g, "/"),
        totalFeeWei,
        executionFeeWei: transaction.executionFeeWei || transaction.gasCostWei || "0",
        blobFeeWei: transaction.blobFeeWei || "0",
      });
    }
  }

  const transactions = [...unique.values()].sort((a, b) => (a.blockNumber || 0) - (b.blockNumber || 0));
  const totals = transactions.reduce((acc, transaction) => {
    const failed = Number(transaction.status) === 0;
    acc.totalFeeWei += wei(transaction.totalFeeWei);
    acc.executionFeeWei += wei(transaction.executionFeeWei);
    acc.blobFeeWei += wei(transaction.blobFeeWei);
    if (failed) acc.revertedFeeWei += wei(transaction.totalFeeWei);
    if (failed) acc.revertedTransactions += 1;
    else acc.successfulTransactions += 1;
    return acc;
  }, { totalFeeWei: 0n, executionFeeWei: 0n, blobFeeWei: 0n, revertedFeeWei: 0n, successfulTransactions: 0, revertedTransactions: 0 });

  writeJson(path.join(ROOT, outputFile), {
    recordedAt: new Date().toISOString(),
    scope: process.env.R2_GAS_LEDGER_SCOPE || "R2 shared deployment, complete root-preparation matrix, all direct settlement paths, all Path-2 claims, and final Path-2/2b settlement transactions.",
    totals: {
      transactionCount: transactions.length,
      successfulTransactions: totals.successfulTransactions,
      revertedTransactions: totals.revertedTransactions,
      totalFeeWei: totals.totalFeeWei.toString(),
      executionFeeWei: totals.executionFeeWei.toString(),
      blobFeeWei: totals.blobFeeWei.toString(),
      revertedFeeWei: totals.revertedFeeWei.toString(),
    },
    transactions,
  });
}

main();
