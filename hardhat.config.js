require("@nomiclabs/hardhat-ethers");
require("@nomiclabs/hardhat-waffle");
require("hardhat-gas-reporter");
require("dotenv").config();

const hardhatNetwork = {
  initialDate: "2023-11-29T00:00:00",
  allowUnlimitedContractSize: true,
  hardfork: "cancun",
};

const sepoliaAccounts = process.env.SEPOLIA_PRIVATE_KEY
  ? [process.env.SEPOLIA_PRIVATE_KEY]
  : [];

if (process.env.MAINNET_RPC_URL) {
  hardhatNetwork.forking = {
    url: process.env.MAINNET_RPC_URL,
  };
  if (process.env.HOP_FORK_BLOCK) {
    hardhatNetwork.forking.blockNumber = Number(process.env.HOP_FORK_BLOCK);
  }
}

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks: {
    hardhat: hardhatNetwork,
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    sepolia: {
      url: `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: sepoliaAccounts,
    },
  },
  gasReporter: {
    currency: 'CHF',
    gasPrice: 21
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: {
          evmVersion: "cancun",
          viaIR: true,
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
    overrides: {
      "contracts/AuroraFullTestnet.sol": {
        version: "0.8.24",
        settings: {
          evmVersion: "cancun",
          viaIR: true,
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
};
