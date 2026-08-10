const operations = require("./operations");

async function runScenarioOperation(scenarioDir, stepName, operationName) {
  const operation = operations[operationName];
  if (!operation) {
    throw new Error(`Unknown operation: ${operationName}`);
  }
  console.log(`[Testnet] ${operationName} -> ${scenarioDir}`);
  await operation(scenarioDir, stepName);
  console.log(`[Testnet] done: ${stepName}`);
}

function main(stepName, operationName, scenarioDir) {
  runScenarioOperation(scenarioDir, stepName, operationName)
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = {
  main,
};
