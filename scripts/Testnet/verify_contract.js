/**
 * verify_contract.js
 *
 * Verify a Solidity contract on Etherscan using API V2 + Standard JSON input.
 * Source is read from Hardhat's artifacts/build-info/ - no flattening needed.
 * Compiler version is auto-detected from build-info.
 *
 * Usage:
 *   node scripts/Testnet/verify_contract.js <address> <file:ContractName> [constructor-args-json] [libraries-json]
 *
 * Arguments:
 *   address              Deployed contract address
 *   file:ContractName    e.g. contracts/AuroraFullTestnet.sol:AuroraFullTestnet
 *   constructor-args-json  JSON array of address args, e.g. '["0ximpl"]'  (optional)
 *   libraries-json       JSON object mapping LibName->address, e.g. '{"AuroraHelperExt":"0x..."}'  (optional)
 *
 * Examples:
 *   node scripts/Testnet/verify_contract.js 0x... contracts/AuroraHelperExt.sol:AuroraHelperExt
 *   node scripts/Testnet/verify_contract.js 0x... contracts/AuroraFullTestnet.sol:AuroraFullTestnet '' '{"AuroraHelperExt":"0x..."}'
 *   node scripts/Testnet/verify_contract.js 0x... contracts/AuroraFactory.sol:AuroraFactory '["0ximpl"]'
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const { ethers } = require("ethers");
require("dotenv").config();

const ETHERSCAN_API = process.env.ETHERSCAN_API_KEY;
const CHAIN_ID = "11155111";
const BUILD_INFO_DIR = path.resolve(__dirname, "../../artifacts/build-info");

function usage() {
  console.log("Usage:");
  console.log("  node scripts/Testnet/verify_contract.js <address> <file:ContractName> [constructor-args-json] [libraries-json]");
  console.log("Examples:");
  console.log("  node scripts/Testnet/verify_contract.js 0x... contracts/AuroraHelperExt.sol:AuroraHelperExt");
  console.log("  node scripts/Testnet/verify_contract.js 0x... contracts/AuroraFullTestnet.sol:AuroraFullTestnet '' '{\"AuroraHelperExt\":\"0x...\"}'");
  console.log("  node scripts/Testnet/verify_contract.js 0x... contracts/AuroraFactory.sol:AuroraFactory '[\"0ximpl\"]'");
}

function post(body) {
  return new Promise((resolve, reject) => {
    const bodyStr = body.toString();
    const req = https.request(
      {
        hostname: "api.etherscan.io",
        path: `/v2/api?chainid=${CHAIN_ID}`,
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(bodyStr),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error(`Invalid JSON: ${data}`)); }
        });
      }
    );
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Invalid JSON: ${data}`)); }
      });
    }).on("error", reject);
  });
}

function findBuildInfo(contractFile) {
  const files = fs.readdirSync(BUILD_INFO_DIR).filter((f) => f.endsWith(".json"));
  for (const file of files) {
    const bi = JSON.parse(fs.readFileSync(path.join(BUILD_INFO_DIR, file), "utf8"));
    if (bi.output && bi.output.contracts && bi.output.contracts[contractFile]) {
      return bi;
    }
  }
  throw new Error(`No build-info found containing ${contractFile}. Run 'npx hardhat compile' first.`);
}

function encodeConstructorArgs(argsJson) {
  if (!argsJson || argsJson === "[]" || argsJson === "") return "";
  const values = JSON.parse(argsJson);
  if (!values || values.length === 0) return "";
  const types = values.map(() => "address");
  return ethers.utils.defaultAbiCoder.encode(types, values).slice(2);
}

async function main() {
  const [, , address, contractRef, constructorArgsJson = "[]", librariesJson = "{}"] = process.argv;
  if (!address || !contractRef) {
    usage();
    process.exit(1);
  }
  if (!ETHERSCAN_API) throw new Error("Missing ETHERSCAN_API_KEY in .env");

  const colonIdx = contractRef.lastIndexOf(":");
  if (colonIdx === -1) {
    console.error("contractRef must be in the form contracts/File.sol:ContractName");
    process.exit(1);
  }
  const contractFile = contractRef.slice(0, colonIdx);
  const contractName = contractRef.slice(colonIdx + 1);

  const bi = findBuildInfo(contractFile);
  const solcVersion = `v${bi.solcLongVersion}`;
  console.log(`Compiler: ${solcVersion}`);

  const input = JSON.parse(JSON.stringify(bi.input));

  const libraries = librariesJson && librariesJson !== "{}" ? JSON.parse(librariesJson) : {};
  if (Object.keys(libraries).length > 0) {
    input.settings = input.settings || {};
    input.settings.libraries = input.settings.libraries || {};
    input.settings.libraries[contractFile] = libraries;
  }

  const constructorArguements = encodeConstructorArgs(constructorArgsJson);

  const params = new URLSearchParams({
    apikey: ETHERSCAN_API,
    module: "contract",
    action: "verifysourcecode",
    contractaddress: address,
    sourceCode: JSON.stringify(input),
    codeformat: "solidity-standard-json-input",
    contractname: `${contractFile}:${contractName}`,
    compilerversion: solcVersion,
    constructorArguements,
    licenseType: "1",
  });

  console.log(`Submitting: ${contractName} at ${address}`);
  const submitRes = await post(params);
  if (submitRes.status !== "1") {
    const msg = (submitRes.result || "").toLowerCase();
    if (msg.includes("already verified")) {
      console.log(`✓ Already verified: https://sepolia.etherscan.io/address/${address}#code`);
      return;
    }
    throw new Error(`Submission failed: ${submitRes.result}`);
  }

  const guid = submitRes.result;
  console.log(`GUID: ${guid}`);

  for (let i = 0; i < 18; i++) {
    await new Promise((r) => setTimeout(r, 10000));
    const statusUrl = `https://api.etherscan.io/v2/api?chainid=${CHAIN_ID}&module=contract&action=checkverifystatus&guid=${guid}&apikey=${ETHERSCAN_API}`;
    const checkRes = await get(statusUrl);
    console.log(`[${(i + 1) * 10}s] ${checkRes.result}`);
    if (checkRes.result === "Pass - Verified" || checkRes.result === "Already Verified") {
      console.log(`✓ https://sepolia.etherscan.io/address/${address}#code`);
      return;
    }
    if (checkRes.result && checkRes.result.startsWith("Fail")) {
      throw new Error(`Verification failed: ${checkRes.result}`);
    }
  }

  throw new Error("Polling timed out after 3 minutes");
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

