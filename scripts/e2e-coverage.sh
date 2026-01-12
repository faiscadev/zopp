#!/bin/bash
set -e

echo "=== Test Coverage Collection ==="

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov"
    exit 1
fi

# The challenge with E2E coverage:
# - E2E tests spawn separate zopp binaries (zopp-server, zopp)
# - These spawned binaries need to be instrumented and write profraw files
#
# Our approach:
# 1. Source llvm-cov environment (sets RUSTFLAGS for instrumentation + LLVM_PROFILE_FILE)
# 2. Build binaries with instrumentation to target/debug
# 3. Run tests, which spawn those instrumented binaries
# 4. Spawned binaries inherit LLVM_PROFILE_FILE and write profraw files on exit
# 5. Generate report from profraw files

# Clean previous coverage data
echo "Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

# Setup coverage environment explicitly
# (source <(...) can have issues with subshell inheritance)
echo "Setting up coverage environment..."
export RUSTFLAGS='-C instrument-coverage --cfg=coverage --cfg=trybuild_no_target'
export LLVM_PROFILE_FILE="$PWD/target/llvm-cov-target/zopp-%p-%m.profraw"
export CARGO_LLVM_COV=1
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target"

# Clean and rebuild instrumented binaries
# Removing the directory ensures fresh build with coverage flags
echo "Building instrumented binaries..."
rm -rf target/llvm-cov-target
cargo build --workspace --bins --target-dir target/llvm-cov-target

# Run E2E tests (spawned binaries inherit coverage env)
echo "Running E2E tests..."

# Run core tests in parallel using llvm-cov test to preserve coverage
cargo llvm-cov test --no-report --package e2e-tests --test demo --test rbac --test principals --test audit --test groups --test invites --test projects --test environments --test user_permissions --no-fail-fast -- --test-threads=4

# Run K8s tests (require Docker and kind, run sequentially)
# Skip only if SKIP_K8S_TESTS=1 is set
if [[ "${SKIP_K8S_TESTS:-}" == "1" ]]; then
    echo "Skipping K8s tests (SKIP_K8S_TESTS=1)"
else
    echo "Running K8s tests..."
    cargo llvm-cov test --no-report --package e2e-tests --test k8s --no-fail-fast -- --test-threads=1
fi

# Generate reports (exclude xtask - dev tooling not part of runtime)
echo "Generating coverage reports..."
mkdir -p coverage
IGNORE_REGEX="xtask/"
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --lcov --output-path coverage/lcov.info
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --html --output-dir coverage/html
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" | tee coverage/summary.txt

echo ""
echo "=== Coverage reports generated ==="
echo "  LCOV: coverage/lcov.info"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
