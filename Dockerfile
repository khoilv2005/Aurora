# Reproducible local evaluation image, following the upstream ALBA artifact model.
FROM node:20-bookworm-slim

WORKDIR /app

# Some transitive dependencies may fall back to native compilation.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
# The inherited ALBA dependency graph contains legacy Hardhat peer ranges.
# Keep the lockfile resolution while accepting those ranges deterministically.
RUN npm ci --legacy-peer-deps

COPY . .

# Resolve the exact Solidity compiler and validate that the project compiles
# before the benchmark is invoked.
RUN npx hardhat compile

# Runs the complete deterministic local lifecycle benchmark and writes
# /app/results/local/lifecycle-benchmark.json.
CMD ["npm", "run", "benchmark:local"]
