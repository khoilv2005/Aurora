# Aurora: Secure and Scalable Cross-Chain Payment Channel Settlement via Merkle Bitmap Accumulators

**Tuan-Dung Tran**, **Van-Khoi Le**, **Quang-Huy Luu**, and **Van-Hau Pham**<br>
Faculty of Computer Networks and Communications, University of Information Technology, Vietnam National University, Ho Chi Minh City, Vietnam<br>

## Abstract

Aurora is a smart-contract implementation and evaluation artifact for batched settlement of Bitcoin payment-channel obligations on Ethereum. The protocol records an ordered on-chain registration ledger, derives a canonical padded Merkle root, and uses bitmap-indexed claims to provide one claim per registered obligation. Ethereum enforces registration structure, root provenance, membership, and settlement transitions. Bitcoin-side semantic validity is monitored off chain and economically protected through collateral, dispute resolution, and a bounded-affiliate collusion model.

The repository contains the Solidity implementation, differential and boundary tests, and immutable artifacts from the completed Ethereum Sepolia evaluation campaign. The archived campaign covers canonical-root submission, lifecycle execution, sparse-claim cases, settlement paths, rejection checks, and runtime-bytecode verification.

**Index Terms—** cross-chain payment channels, Bitcoin, Ethereum, EIP-4844, Merkle trees, smart contracts, economic security.

## Repository Contents

**Provenance.** This repository is derived from the [original ALBA protocol codebase](https://github.com/scaffino/Alba-Bridge) and its archived [ALBA smart-contract artifact](https://doi.org/10.5281/zenodo.14249987). It retains the underlying Bitcoin transaction-processing and verification components, and adds Aurora's registered-intent ledger, canonical Merkle accumulator, bitmap-based claims, associated tests, and the accompanying Sepolia evaluation artifacts.

```text
contracts/                     Solidity contracts and verification helpers
test/                          Hardhat unit, invariant, and benchmark tests
results/local/                 Reproducible local-lifecycle benchmark artifact
data/                          Bitcoin-side test vectors and Sepolia dispute vectors
python-bitcoin-utils/          Bitcoin transaction and dispute-vector utilities
scripts/Testnet/               Sepolia deployment, execution, and validation utilities
scripts/local/                 Local benchmark runner
RESULTS_MAP.md                 Metric-to-artifact traceability map
Dockerfile                     Reproducible local-evaluation container
```

The [final Sepolia metrics artifact](scripts/Testnet/r2/full/scenarios/final-r2-metrics.json) records the completed campaign.

It records 19 root scenarios, 779 completed claims, five direct settlement paths, gas ledgers, transaction receipts, runtime-bytecode verification, and reverted-call evidence. All reported gas values are transaction `gasUsed`; ETH fees and blob fees remain in the raw artifacts for cost reconstruction.

## Reproducibility

The Docker workflow installs the pinned dependencies, compiles the contracts, runs the complete local lifecycle benchmark, and writes the resulting JSON artifact to the mounted `results/` directory.

```bash
docker build --no-cache -t aurora .
docker run --rm --mount "type=bind,source=$($PWD.Path)\results,target=/app/results" aurora
```

## Scope and Security Boundary

Aurora does not parse Bitcoin transaction semantics on Ethereum in the common settlement path. Its on-chain guarantees are structural: amount-cap enforcement, sequential registration indexing, contract-derived obligation count and registered total, canonical-root equality, and one-claim-per-index settlement. Bitcoin-side semantic validity requires active verification, collateralized dispute execution, and the stated deployment assumption that affiliate-controlled registrations remain bounded below the full batch.

## License

This artifact is released under the [MIT License](LICENSE).
