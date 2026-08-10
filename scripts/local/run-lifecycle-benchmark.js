const { execFileSync } = require("child_process");
const path = require("path");

const repositoryRoot = path.resolve(__dirname, "..", "..");
const outputPath = path.join(repositoryRoot, "results", "local", "lifecycle-benchmark.json");
const npxCommand = process.platform === "win32" ? "npx.cmd" : "npx";

console.log("Running the local Aurora lifecycle benchmark; this produces a reproducible gas artifact.");
execFileSync(npxCommand, ["hardhat", "test", "test/AuroraR2Benchmark.test.js"], {
  cwd: repositoryRoot,
  env: { ...process.env, AURORA_BENCHMARK_OUT: outputPath },
  shell: process.platform === "win32",
  stdio: "inherit",
});
console.log(`Wrote benchmark artifact: ${outputPath}`);
