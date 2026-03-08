#!/bin/sh
# zopp CLI installer (redirects to scripts/install.sh)
# Usage: curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$SCRIPT_DIR/scripts/install.sh" ]; then
    exec sh "$SCRIPT_DIR/scripts/install.sh" "$@"
fi

# When piped from curl, the script directory won't contain scripts/install.sh.
# In that case, download and run the canonical script from GitHub.
exec curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/scripts/install.sh | sh -s -- "$@"
