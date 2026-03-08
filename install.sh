#!/bin/sh
# zopp CLI installer (redirects to scripts/install.sh)
# Usage: curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
set -e

# Only attempt local delegation when executed from a file, not piped via stdin
if [ -f "$0" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$SCRIPT_DIR/scripts/install.sh" ]; then
        exec sh "$SCRIPT_DIR/scripts/install.sh" "$@"
    fi
fi

# Download the canonical script first, then execute it
ZOPP_TMPSCRIPT=$(mktemp)
trap 'rm -f "$ZOPP_TMPSCRIPT"' EXIT
curl -fsSL -o "$ZOPP_TMPSCRIPT" https://raw.githubusercontent.com/faiscadev/zopp/main/scripts/install.sh
exec sh "$ZOPP_TMPSCRIPT" "$@"
