# Results Map

This document maps each reported gas result to a versioned artifact in this repository. It distinguishes local Hardhat measurements from Ethereum Sepolia transaction measurements. Values from the two environments are not substituted for one another.

## Reproducing the Local Artifact

The committed local artifact was generated on `2026-08-10T11:55:25.571Z` using a Hardhat network (`chainId = 31337`, block gas limit `60,000,000`). Re-run it with:

```bash
npm ci
npm run benchmark:local
```

The command overwrites `results/local/lifecycle-benchmark.json`. It exercises the same registered ledger through both the incremental implementation and the reference implementation for `n = {1, 3, 16, 17, 64, 65, 128, 129, 256}`. Each run registers the obligations, submits the canonical padded root in a blob transaction, claims every registered index, and settles the batch.

## Local Lifecycle Results

The following values are `gasUsed` from the incremental implementation in `results/local/lifecycle-benchmark.json` (`results[]` entries where `variant = "incremental"`). `Lifecycle gas` includes batch creation, setup-related calls, the user-protection-pool deposit, all registrations, root submission, all claims, and settlement.

| `n` | `N'` | Register / obligation | Root submission | First claim | Subsequent claim | Settle | Lifecycle gas | Lifecycle / obligation | Max receipt gas |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 168,938 | 245,803 | 108,915 | — | 77,706 | 1,324,645 | 1,324,645 | 397,272 |
| 3 | 4 | 141,289 | 249,763 | 115,625 | 81,470 | 77,706 | 1,748,385 | 582,795 | 397,272 |
| 16 | 16 | 127,513 | 246,427 | 117,488 | 83,333 | 77,706 | 4,451,014 | 278,188 | 397,272 |
| 17 | 32 | 126,932 | 254,666 | 118,437 | 84,282 | 77,706 | 4,676,369 | 275,081 | 397,272 |
| 64 | 64 | 122,555 | 246,739 | 119,387 | 85,232 | 77,706 | 14,379,876 | 224,685 | 397,272 |
| 65 | 128 | 122,479 | 259,536 | 120,336 | 86,181 | 77,706 | 14,657,228 | 225,496 | 397,272 |
| 128 | 128 | 121,506 | 246,895 | 120,336 | 86,181 | 77,706 | 27,671,627 | 216,185 | 397,272 |
| 129 | 256 | 121,477 | 262,441 | 121,286 | 87,131 | 77,706 | 28,013,554 | 217,159 | 397,272 |
| 256 | 256 | 120,915 | 247,051 | 121,286 | 87,131 | 77,706 | 54,359,841 | 212,343 | 397,272 |

### Local Reference Comparison

The reference implementation reconstructs the registration root; it is retained as a correctness oracle. For the same ledger, the incremental and reference roots are asserted equal by the benchmark. The root-submission gas below is mapped to the corresponding `results[]` entry in `results/local/lifecycle-benchmark.json`.

| `n` | Incremental root submission | Reference root submission | Difference |
|---:|---:|---:|---:|
| 1 | 245,803 | 249,532 | 3,729 |
| 16 | 246,427 | 343,692 | 97,265 |
| 64 | 246,739 | 646,560 | 399,821 |
| 128 | 246,895 | 1,056,954 | 810,059 |
| 256 | 247,051 | 1,900,892 | 1,653,841 |

Deployment measurements are also preserved in the local artifact: incremental implementation `7,457,124` gas, reference implementation `7,452,804` gas, and each factory `305,419` gas.

## Completed Sepolia Campaign

The Sepolia campaign is summarized by `scripts/Testnet/r2/full/scenarios/final-r2-metrics.json`, generated on `2026-08-08T03:23:56.756Z`. It records `19` root scenarios, `779` completed claims, `19` Path-2 settlements, `5` direct settlement-path scenarios, `3,677` final transactions, and one reverted transaction. All values below are transaction `gasUsed` on Sepolia.

| Scenario | `n` | `N'` | Registration average | Root submission | Source fields |
|---|---:|---:|---:|---:|---|
| `b1_submit_n001` | 1 | 1 | 168,959 | 245,803 | `rootSubmission[0]` |
| `b1_submit_n016` | 16 | 16 | 127,533 | 246,427 | `rootSubmission[1]` |
| `b1_submit_n064` | 64 | 64 | 122,576 | 246,739 | `rootSubmission[2]` |
| `b1_submit_n128` | 128 | 128 | 121,528 | 246,895 | `rootSubmission[3]` |
| `b6_sparse_n256_f50` | 256 | 256 | 120,937 | 247,051 | `rootSubmission[4]` |

Representative complete protocol lifecycles are `27,743,173` gas for `b2_lifecycle_n128` and `48,165,630` gas for `b6_sparse_n256_f50`; their exact receipt lists are in `representativeProtocolLifecycles` of the final-metrics artifact. The five direct paths and their total gas are: Path 1 `1,106,024`, Path 1b `1,455,080`, Path 3 `1,306,490`, Path 4 `1,290,757`, and Path 5 `390,056`; see `directPaths[]` in that artifact.

## Source Map

| Result family | Canonical source | How to inspect |
|---|---|---|
| Local deployment, registration, root, claim, settlement, and lifecycle gas | `results/local/lifecycle-benchmark.json` | Read `deploymentGas` and `results[]`; each entry is keyed by `variant`, `n`, and `paddedN`. |
| Local reference/incremental equality | `results/local/lifecycle-benchmark.json` and `test/AuroraR2Benchmark.test.js` | The test compares `referenceRegistrationMerkleRoot` and `registrationAccumulatorRoot` with the independently reconstructed root before submission. |
| Sepolia root and registration gas | `scripts/Testnet/r2/full/scenarios/final-r2-metrics.json` | Read `rootSubmission[]`, then follow each listed `sources[]` receipt. |
| Sepolia full and sparse lifecycle gas | `scripts/Testnet/r2/full/scenarios/final-r2-metrics.json` | Read `lifecycle`, `representativeProtocolLifecycles`, and the listed receipts. |
| Sepolia settlement-path gas | `scripts/Testnet/r2/full/scenarios/final-r2-metrics.json` | Read `directPaths[]` and follow each `sources[]` receipt. |
| Complete transaction ledger, execution fees, and blob fees | `scripts/Testnet/r2/full/scenarios/gas-ledger-final.json` | Filter by scenario identifier and transaction label. |
| Completion, checkpoint, and reverted-call evidence | `scripts/Testnet/r2/full/scenarios/{launch-report,claim-wait-checkpoint,settlement-wait-checkpoint}.json` | Inspect the scenario-level checkpoint records. |

## Interpretation Notes

- Local results establish implementation behavior, root equivalence, padding behavior, and block-limit feasibility under the deterministic Hardhat environment.
- Sepolia results establish that the deployed implementation executes the recorded protocol paths with real RPC, transaction receipts, event traces, and blob-fee evidence.
- Cross-environment comparisons use gas units only. The Sepolia artifacts preserve execution and blob fees separately; ETH-denominated fees are not used as local-to-testnet performance comparisons.
- “First” and “subsequent” claim refer to the measured bitmap-state transition in separate transactions; they do not describe EIP-2929 storage warmth persisting across transactions.
