const { ethers } = require("hardhat");
async function main() {
  const deployer = new ethers.Wallet(process.env.SEPOLIA_PRIVATE_KEY, ethers.provider);
  const prover   = new ethers.Wallet(process.env.TESTNET_PROVER_PRIVATE_KEY, ethers.provider);
  const dBal = await ethers.provider.getBalance(deployer.address);
  const pBal = await ethers.provider.getBalance(prover.address);
  console.log("Deployer", deployer.address, ethers.utils.formatEther(dBal), "ETH");
  console.log("Prover  ", prover.address,   ethers.utils.formatEther(pBal), "ETH");
}
main().catch(console.error);
