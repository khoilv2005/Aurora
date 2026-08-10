const EXPLORER_BY_NETWORK = {
  sepolia: "https://sepolia.etherscan.io",
  hardhat: "",
  localhost: "",
};

const SECONDS = {
  challengeWindow: 24 * 60 * 60,
  claimWindow: 7 * 24 * 60 * 60,
};

// AuroraFullTestnet emits stateEvent(string code, bool value) - string keys "S1".."S13"
const STATE_EVENT_CODES = {
  "S1":  "Proof submitted",
  "S2":  "Proof submission failed",
  "S3":  "Dispute opened",
  "S4":  "Dispute open failed",
  "S5":  "Valid dispute resolved",
  "S6":  "Invalid dispute resolved",
  "S7":  "Settle Path 1 (proof accepted)",
  "S8":  "Settle Path 2 (partial claims)",
  "S9":  "Settle Path 2b (zero claims)",
  "S10": "Settle Path 3 (dispute frozen)",
  "S11": "Settle Path 4 (revocation)",
  "S12": "Settle Path 5 (no setup)",
  "S13": "Arbitration timeout (D burned)",
};

module.exports = {
  EXPLORER_BY_NETWORK,
  SECONDS,
  STATE_EVENT_CODES,
};

