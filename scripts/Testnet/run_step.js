const path = require("path");
const { main } = require("./lib/runtime");

const [, , scenarioRelativeDir, stepName, operationName] = process.argv;

if (!scenarioRelativeDir || !stepName || !operationName) {
  console.error("Usage: node scripts/Testnet/run_step.js <scenario-dir> <step-name> <operation-name>");
  process.exit(1);
}

main(stepName, operationName, path.resolve(__dirname, scenarioRelativeDir));
