#!/usr/bin/env bash
set -euo pipefail

# Unit test coverage script
# Requires: cargo-llvm-cov (install with: cargo install cargo-llvm-cov)

mkdir -p coverage

echo "Running unit tests with coverage..."

# Run unit tests with coverage (exclude e2e-tests and xtask)
cargo llvm-cov \
    --workspace \
    --exclude e2e-tests \
    --exclude xtask \
    --all-features \
    --html \
    --output-dir coverage/html

# Generate text summary for CI parsing
cargo llvm-cov \
    --workspace \
    --exclude e2e-tests \
    --exclude xtask \
    --all-features \
    --no-run \
    > coverage/summary.txt

echo ""
echo "Coverage report generated:"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
echo ""
cat coverage/summary.txt
