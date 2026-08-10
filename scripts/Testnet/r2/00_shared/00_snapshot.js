const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const root = path.resolve(__dirname, "../../../..");
const artifactRoot = path.join(root, "artifacts", "contracts");
const outputPath = path.join(__dirname, "artifacts", "pre_deployment_snapshot.json");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readArtifact(sourceName, contractName) {
  const artifactPath = path.join(artifactRoot, sourceName, `${contractName}.json`);
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return {
    artifactPath: path.relative(root, artifactPath).replaceAll("\\", "/"),
    abiSha256: sha256(JSON.stringify(artifact.abi)),
    creationBytecodeSha256: sha256(artifact.bytecode),
    runtimeBytecodeSha256: sha256(artifact.deployedBytecode),
    linkReferences: artifact.linkReferences,
  };
}

function optionalHash(fileName) {
  const filePath = path.join(root, fileName);
  return fs.existsSync(filePath) ? sha256(fs.readFileSync(filePath)) : null;
}

const snapshot = {
  createdAt: new Date().toISOString(),
  gitCommit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  gitDirty: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
  lockfileSha256: optionalHash("package-lock.json") || optionalHash("yarn.lock"),
  contracts: {
    AuroraHelperExt: readArtifact("AuroraHelperExt.sol", "AuroraHelperExt"),
    AuroraFullTestnet: readArtifact("AuroraFullTestnet.sol", "AuroraFullTestnet"),
    AuroraFactory: readArtifact("AuroraFactory.sol", "AuroraFactory"),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(snapshot, null, 2) + "\n");
console.log(`Wrote ${path.relative(root, outputPath)}`);
console.log(`gitCommit=${snapshot.gitCommit} gitDirty=${snapshot.gitDirty}`);
