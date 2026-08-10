# Aurora: Secure and Scalable Cross-Chain Payment Channel Settlement via Merkle Bitmap Accumulators

**Tuan-Dung Tran**, **Van-Khoi Le**, **Quang-Huy Luu**, and **Van-Hau Pham***<br>
Faculty of Computer Networks and Communications, University of Information Technology, Vietnam National University, Ho Chi Minh City, Vietnam<br>
\*Corresponding author: Van-Hau Pham

## Abstract

Aurora is a smart-contract implementation and evaluation artifact for batched settlement of Bitcoin payment-channel obligations on Ethereum. The protocol records an ordered on-chain registration ledger, derives a canonical padded Merkle root, and uses bitmap-indexed claims to provide one claim per registered obligation. Ethereum enforces registration structure, root provenance, membership, and settlement transitions. Bitcoin-side semantic validity is monitored off chain and economically protected through collateral, dispute resolution, and a bounded-affiliate collusion model.

The repository contains the Solidity implementation, differential and boundary tests, and immutable artifacts from the completed Ethereum Sepolia evaluation campaign. The archived campaign covers canonical-root submission, lifecycle execution, sparse-claim cases, settlement paths, rejection checks, and runtime-bytecode verification.

**Index Terms—** cross-chain payment channels, Bitcoin, Ethereum, EIP-4844, Merkle trees, smart contracts, economic security.

## Repository Contents

**Provenance.** This repository is derived from the original ALBA protocol codebase. It retains the underlying Bitcoin transaction-processing and verification components, and adds Aurora's registered-intent ledger, canonical Merkle accumulator, bitmap-based claims, associated tests, and the accompanying Sepolia evaluation artifacts.

```text
contracts/                     Solidity contracts and verification helpers
test/                          Hardhat unit, invariant, and benchmark tests
data/                          Bitcoin-side test vectors and Sepolia dispute vectors
python-bitcoin-utils/          Bitcoin transaction and dispute-vector utilities
scripts/Testnet/lib/           Shared testnet execution utilities
scripts/Testnet/r2/            Testnet deployment scripts and latest Sepolia artifacts
scripts/Testnet/r2/full/       Complete campaign orchestration and final metrics
```

The final testnet summary is at:

```text
scripts/Testnet/r2/full/scenarios/final-r2-metrics.json
```

It records 19 root scenarios, 779 completed claims, five direct settlement paths, gas ledgers, transaction receipts, runtime-bytecode verification, and reverted-call evidence. All reported gas values are transaction `gasUsed`; ETH fees and blob fees remain in the raw artifacts for cost reconstruction.

## Reproducibility

### Prerequisites

- Node.js 18 or later
- npm 9 or later
- A Sepolia RPC endpoint and funded test account only when re-running deployment scripts

### Local validation

```bash
npm ci
npx hardhat compile
npx hardhat test test/AuroraR2.test.js
npx hardhat test test/AuroraR2Benchmark.test.js
```

### Testnet configuration

Create a local `.env` file that is never committed:

```text
ALCHEMY_API_KEY=<your Sepolia RPC key>
SEPOLIA_PRIVATE_KEY=<your funded deployment key>
ETHERSCAN_API_KEY=<optional verification key>
```

The completed campaign is preserved as an artifact and should be inspected before any new deployment. To reproduce a new campaign, use the deployment scripts in `scripts/Testnet/r2/`; these scripts send transactions and therefore consume Sepolia ETH.

```bash
npx hardhat run scripts/Testnet/r2/00_shared/01_deploy.js --network sepolia
node scripts/Testnet/r2/full/launch.js
node scripts/Testnet/r2/full/generate_final_metrics.js
```

## Scope and Security Boundary

Aurora does not parse Bitcoin transaction semantics on Ethereum in the common settlement path. Its on-chain guarantees are structural: amount-cap enforcement, sequential registration indexing, contract-derived obligation count and registered total, canonical-root equality, and one-claim-per-index settlement. Bitcoin-side semantic validity requires active verification, collateralized dispute execution, and the stated deployment assumption that affiliate-controlled registrations remain bounded below the full batch.

## License

This artifact is released under the [MIT License](LICENSE).
