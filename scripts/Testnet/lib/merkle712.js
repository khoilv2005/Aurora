/**
 * @file merkle712.js
 * @dev EIP-712 aware Merkle tree helpers for AuroraFull / AuroraFullTestnet.
 *      Mirrors the JS logic in test/Benchmark.test.js, but chain-ID aware
 *      so the same code works on Hardhat (chainId=31337) and Sepolia (chainId=11155111).
 */
const { ethers } = require("hardhat");

const LEAF_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index)")
);
const DOMAIN_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  )
);

function getDomainSeparator(chainId, contractAddr) {
  return ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        DOMAIN_TYPEHASH,
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")),
        chainId,
        contractAddr,
      ]
    )
  );
}

function leafHash712(chainId, contractAddr, addr, amount, index) {
  const ds = getDomainSeparator(chainId, contractAddr);
  const structHash = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "address", "uint256", "uint256"],
      [LEAF_TYPEHASH, addr, ethers.BigNumber.from(amount), index]
    )
  );
  return ethers.utils.keccak256(
    ethers.utils.concat([
      ethers.utils.arrayify("0x1901"),
      ethers.utils.arrayify(ds),
      ethers.utils.arrayify(structHash),
    ])
  );
}

function hashPair(a, b) {
  return ethers.utils.keccak256(
    ethers.utils.solidityPack(["bytes32", "bytes32"], [a, b])
  );
}

/**
 * Build an EIP-712 Merkle tree.
 * Leaf node = keccak256(leafHash712(...)) - mirrors verifyMerkleProof on-chain.
 */
function buildMerkleTree712(chainId, contractAddr, addrs, amounts) {
  let currentLevel = addrs.map((addr, i) => {
    const leaf = leafHash712(chainId, contractAddr, addr, amounts[i], i);
    return ethers.utils.keccak256(leaf); // double-hash: mirrors verifyMerkleProof
  });
  const tree = [currentLevel.slice()];
  while (currentLevel.length > 1) {
    const next = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      next.push(
        i + 1 < currentLevel.length
          ? hashPair(currentLevel[i], currentLevel[i + 1])
          : currentLevel[i]
      );
    }
    tree.push(next);
    currentLevel = next;
  }
  return { root: currentLevel[0], tree };
}

function getMerkleProof712(tree, index) {
  const proof = [];
  let idx = index;
  for (let level = 0; level < tree.length - 1; level++) {
    const nodes = tree[level];
    const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (sib < nodes.length) proof.push(nodes[sib]);
    idx = Math.floor(idx / 2);
  }
  return proof;
}

module.exports = {
  getDomainSeparator,
  leafHash712,
  buildMerkleTree712,
  getMerkleProof712,
};

