const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");

const root = path.resolve(__dirname, "../../../..");
const shared = JSON.parse(fs.readFileSync(path.join(root, "scripts", "Testnet", "shared", "sepolia-aurora-r2.json"), "utf8"));
const artifact = JSON.parse(fs.readFileSync(
  path.join(root, "artifacts", "contracts", "AuroraFullTestnet.sol", "AuroraFullTestnet.json"), "utf8"
));

let linkedRuntime = artifact.deployedBytecode.slice(2);
for (const references of Object.values(artifact.deployedLinkReferences || artifact.linkReferences)) {
  for (const entries of Object.values(references)) {
    for (const { start, length } of entries) {
      const address = shared.libAddress.slice(2).toLowerCase();
      if (length !== 20) throw new Error(`Unexpected library-reference length: ${length}`);
      linkedRuntime = linkedRuntime.slice(0, start * 2) + address + linkedRuntime.slice((start + length) * 2);
    }
  }
}

async function main() {
  const actualRuntime = (await ethers.provider.getCode(shared.implementationAddress)).slice(2).toLowerCase();
  const expectedRuntime = linkedRuntime.toLowerCase();
  const result = {
    implementationAddress: shared.implementationAddress,
    expectedRuntimeSha256: crypto.createHash("sha256").update(Buffer.from(expectedRuntime, "hex")).digest("hex"),
    deployedRuntimeSha256: crypto.createHash("sha256").update(Buffer.from(actualRuntime, "hex")).digest("hex"),
    bytecodeMatches: actualRuntime === expectedRuntime,
  };
  if (!result.bytecodeMatches) throw new Error(JSON.stringify(result));
  const outputPath = path.join(__dirname, "artifacts", "runtime_verification.json");
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result));
}

main().catch((error) => { console.error(error); process.exit(1); });
