/**
 * Registration-indexed Merkle helpers for Aurora R2.
 * Mirrors AuroraFullTestnet: EIP-712 leaf digest, an outer leaf hash,
 * deterministic fixed dummy leaves, and ordered (non-sorted) pair hashing.
 */
const { ethers } = require("hardhat");

const LEAF_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes("AuroraLeaf(address addr,uint256 amount,uint256 index,bytes32 obligationCommitment)")
);
const DOMAIN_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
);

function obligationCommitment(index) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`aurora-r2-obligation-${index}`));
}

function hashPair(left, right) {
  return ethers.utils.keccak256(ethers.utils.solidityPack(["bytes32", "bytes32"], [left, right]));
}

function leafHash(chainId, contractAddress, registration, index) {
  const domain = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [DOMAIN_TYPEHASH, ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Aurora")),
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes("1")), chainId, contractAddress]
  ));
  const structHash = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
    ["bytes32", "address", "uint256", "uint256", "bytes32"],
    [LEAF_TYPEHASH, registration.addr, registration.amount, index, registration.obligationCommitment]
  ));
  return ethers.utils.keccak256(ethers.utils.concat([
    ethers.utils.arrayify("0x1901"), ethers.utils.arrayify(domain), ethers.utils.arrayify(structHash),
  ]));
}

function buildRegistrationTree(chainId, contractAddress, registrations) {
  if (registrations.length === 0) throw new Error("R2 registration ledger must be non-empty");
  let padded = 1;
  while (padded < registrations.length) padded <<= 1;
  const dummy = ethers.utils.keccak256(
    ethers.utils.solidityPack(["string", "address"], ["AURORA_DUMMY", contractAddress])
  );
  let nodes = Array.from({ length: padded }, (_, index) =>
    index < registrations.length ? ethers.utils.keccak256(leafHash(chainId, contractAddress, registrations[index], index)) : dummy
  );
  const tree = [nodes];
  while (nodes.length > 1) {
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) next.push(hashPair(nodes[index], nodes[index + 1]));
    tree.push(next);
    nodes = next;
  }
  return { root: nodes[0], padded, tree };
}

function proofFor(tree, index) {
  const proof = [];
  for (let level = 0, cursor = index; level < tree.length - 1; level++, cursor >>= 1) {
    proof.push(tree[level][cursor % 2 === 0 ? cursor + 1 : cursor - 1]);
  }
  return proof;
}

module.exports = { obligationCommitment, buildRegistrationTree, proofFor };
