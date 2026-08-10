const { ethers } = require("hardhat");

function hashLeaf(data) {
  return ethers.utils.keccak256(data);
}

function hashPair(a, b) {
  return ethers.utils.keccak256(
    ethers.utils.solidityPack(["bytes32", "bytes32"], [a, b])
  );
}

function buildLeafData(contractAddress, addr, amount, index) {
  return ethers.utils.defaultAbiCoder.encode(
    ["address", "address", "uint256", "uint256"],
    [contractAddress, addr, amount, index]
  );
}

// Returns the smallest power of 2 >= n (minimum 1).
function nextPowerOf2(n) {
  if (n <= 1) return 1;
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

function buildMerkleTree(rawDataArray) {
  // Pad to next power of 2 by repeating the last element.
  // This ensures every level is even-sized so the contract's
  // verifyMerkleProof (which divides originalIndex >> k per step) is correct.
  // Padded slots are beyond batchSize and cannot be claimed on-chain.
  const size = nextPowerOf2(rawDataArray.length);
  const padded = rawDataArray.slice();
  while (padded.length < size) padded.push(padded[padded.length - 1]);

  const rawLeafHashes = padded.map((data) => hashLeaf(data));
  let currentLevel = rawLeafHashes.map((hash) =>
    ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32"], [hash]))
  );
  const tree = [currentLevel.slice()];
  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      nextLevel.push(hashPair(currentLevel[i], currentLevel[i + 1]));
    }
    tree.push(nextLevel);
    currentLevel = nextLevel;
  }
  return { root: currentLevel[0], rawLeafHashes, tree };
}

function getMerkleProof(tree, index) {
  const proof = [];
  let idx = index;
  for (let level = 0; level < tree.length - 1; level++) {
    const levelNodes = tree[level];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (siblingIdx < levelNodes.length) {
      proof.push(levelNodes[siblingIdx]);
    }
    idx = Math.floor(idx / 2);
  }
  return proof;
}

module.exports = {
  buildLeafData,
  buildMerkleTree,
  getMerkleProof,
};
