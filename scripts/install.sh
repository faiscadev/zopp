#!/bin/sh
# zopp CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/scripts/install.sh | sh
set -e

ZOPP_INSTALLER_VERSION="1.0"
ZOPP_REPO="faiscadev/zopp"
ZOPP_INSTALL_DIR="${ZOPP_INSTALL_DIR:-$HOME/.zopp/bin}"

# --- Output helpers ---

zopp_use_color() {
    if [ -n "$NO_COLOR" ] || [ "$ZOPP_NO_COLOR" = "1" ]; then
        return 1
    fi
    # Check if stdout is a TTY
    if [ -t 1 ]; then
        return 0
    fi
    return 1
}

zopp_log() {
    printf "  %s\n" "$1"
}

zopp_log_success() {
    if zopp_use_color; then
        printf "  \033[32m\033[1m%s\033[0m %s\n" "ok" "$1"
    else
        printf "  [ok] %s\n" "$1"
    fi
}

zopp_log_error() {
    if zopp_use_color; then
        printf "  \033[31m\033[1m%s\033[0m %s\n" "FAIL" "$1" >&2
    else
        printf "  [FAIL] %s\n" "$1" >&2
    fi
}

zopp_log_warn() {
    if zopp_use_color; then
        printf "  \033[33m%s\033[0m %s\n" "WARN" "$1"
    else
        printf "  [WARN] %s\n" "$1"
    fi
}

# --- Platform detection ---

zopp_detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64)
                    ZOPP_TARGET="x86_64-unknown-linux-gnu"
                    ZOPP_PLATFORM_DISPLAY="Linux x86_64"
                    ;;
                aarch64)
                    ZOPP_TARGET="aarch64-unknown-linux-gnu"
                    ZOPP_PLATFORM_DISPLAY="Linux aarch64 (ARM64)"
                    ;;
                *)
                    zopp_log_error "Unsupported architecture: $ARCH"
                    zopp_log ""
                    zopp_log "Supported platforms:"
                    zopp_log "  - Linux x86_64"
                    zopp_log "  - Linux aarch64 (ARM64)"
                    zopp_log "  - macOS x86_64 (Intel)"
                    zopp_log "  - macOS aarch64 (Apple Silicon)"
                    zopp_log ""
                    zopp_log "Alternatively, install from source: cargo install --git https://github.com/$ZOPP_REPO zopp-cli"
                    exit 1
                    ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                x86_64)
                    ZOPP_TARGET="x86_64-apple-darwin"
                    ZOPP_PLATFORM_DISPLAY="macOS x86_64 (Intel)"
                    ;;
                arm64)
                    ZOPP_TARGET="aarch64-apple-darwin"
                    ZOPP_PLATFORM_DISPLAY="macOS aarch64 (Apple Silicon)"
                    ;;
                *)
                    zopp_log_error "Unsupported architecture: $ARCH"
                    zopp_log ""
                    zopp_log "Supported platforms:"
                    zopp_log "  - macOS x86_64 (Intel)"
                    zopp_log "  - macOS aarch64 (Apple Silicon)"
                    zopp_log "  - Linux x86_64"
                    zopp_log "  - Linux aarch64 (ARM64)"
                    zopp_log ""
                    zopp_log "Alternatively, install from source: cargo install --git https://github.com/$ZOPP_REPO zopp-cli"
                    exit 1
                    ;;
            esac
            ;;
        *)
            zopp_log_error "Unsupported operating system: $OS"
            zopp_log ""
            zopp_log "Supported platforms:"
            zopp_log "  - Linux x86_64"
            zopp_log "  - Linux aarch64 (ARM64)"
            zopp_log "  - macOS x86_64 (Intel)"
            zopp_log "  - macOS aarch64 (Apple Silicon)"
            zopp_log ""
            zopp_log "Alternatively, install from source: cargo install --git https://github.com/$ZOPP_REPO zopp-cli"
            exit 1
            ;;
    esac
}

# --- Version fetching ---

zopp_fetch_version() {
    LATEST_URL="https://api.github.com/repos/$ZOPP_REPO/releases/latest"
    VERSION=$(curl -fsSL "$LATEST_URL" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$VERSION" ]; then
        zopp_log_error "Could not fetch latest version from GitHub Releases."
        zopp_log "  Check your internet connection and try again."
        zopp_log "  URL: $LATEST_URL"
        exit 1
    fi
}

# --- Checksum verification ---

zopp_compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        zopp_log_warn "Neither sha256sum nor shasum found. Skipping checksum verification."
        echo ""
    fi
}

zopp_verify_checksum() {
    ARCHIVE_PATH="$1"
    CHECKSUMS_PATH="$2"
    ARCHIVE_NAME="$3"

    EXPECTED=$(grep "$ARCHIVE_NAME" "$CHECKSUMS_PATH" | awk '{print $1}')

    if [ -z "$EXPECTED" ]; then
        zopp_log_warn "No checksum found for $ARCHIVE_NAME in checksums.txt. Skipping verification."
        return 0
    fi

    ACTUAL=$(zopp_compute_sha256 "$ARCHIVE_PATH")

    if [ -z "$ACTUAL" ]; then
        # sha256sum/shasum not available, already warned
        return 0
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        zopp_log_error "SHA256 checksum verification failed!"
        zopp_log ""
        zopp_log "  Expected: $EXPECTED"
        zopp_log "  Actual:   $ACTUAL"
        zopp_log ""
        zopp_log "  The downloaded file may be corrupted or tampered with."
        zopp_log "  Try again, or download manually from:"
        zopp_log "  https://github.com/$ZOPP_REPO/releases"
        exit 1
    fi
}

# --- Main install logic ---

zopp_install() {
    zopp_detect_platform

    zopp_log ""
    zopp_log "zopp installer v$ZOPP_INSTALLER_VERSION"
    zopp_log ""
    zopp_log "Detected: $ZOPP_PLATFORM_DISPLAY"

    zopp_fetch_version
    zopp_log "Latest:   zopp $VERSION"
    zopp_log ""

    # Set up temp directory
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    ARCHIVE_NAME="zopp-$ZOPP_TARGET.tar.gz"
    DOWNLOAD_URL="https://github.com/$ZOPP_REPO/releases/download/$VERSION/$ARCHIVE_NAME"
    CHECKSUMS_URL="https://github.com/$ZOPP_REPO/releases/download/$VERSION/checksums.txt"

    # Download archive
    printf "  Downloading..."
    if curl -fsSL -o "$TMPDIR/$ARCHIVE_NAME" "$DOWNLOAD_URL"; then
        zopp_log_success ""
    else
        printf "\n"
        zopp_log_error "Download failed."
        zopp_log "  URL: $DOWNLOAD_URL"
        zopp_log "  Check your internet connection and try again."
        exit 1
    fi

    # Download checksums and verify
    printf "  Verifying checksum..."
    if curl -fsSL -o "$TMPDIR/checksums.txt" "$CHECKSUMS_URL"; then
        zopp_verify_checksum "$TMPDIR/$ARCHIVE_NAME" "$TMPDIR/checksums.txt" "$ARCHIVE_NAME"
        zopp_log_success "(SHA256 matched)"
    else
        zopp_log_warn "Could not download checksums.txt. Skipping verification."
    fi

    # Extract
    tar -xzf "$TMPDIR/$ARCHIVE_NAME" -C "$TMPDIR"

    # Install
    mkdir -p "$ZOPP_INSTALL_DIR"

    printf "  Installing to %s..." "$ZOPP_INSTALL_DIR/zopp"
    if mv "$TMPDIR/zopp" "$ZOPP_INSTALL_DIR/zopp" 2>/dev/null; then
        chmod +x "$ZOPP_INSTALL_DIR/zopp"
        zopp_log_success ""
    else
        printf "\n"
        zopp_log_error "Could not install to $ZOPP_INSTALL_DIR."
        zopp_log "  Permission denied. Try one of:"
        zopp_log "    ZOPP_INSTALL_DIR=/path/to/dir sh install.sh"
        zopp_log "    sudo sh install.sh"
        exit 1
    fi

    zopp_log ""
    zopp_log "zopp $VERSION installed successfully!"

    # PATH check
    case ":$PATH:" in
        *":$ZOPP_INSTALL_DIR:"*)
            ;;
        *)
            zopp_log ""
            zopp_log_warn "$ZOPP_INSTALL_DIR is not in your PATH."
            zopp_log "  Add it by running:"
            zopp_log "    export PATH=\"$ZOPP_INSTALL_DIR:\$PATH\""
            zopp_log ""
            zopp_log "  To make it permanent, add that line to your shell profile:"
            zopp_log "    ~/.bashrc, ~/.zshrc, or ~/.profile"
            ;;
    esac

    zopp_log ""
    zopp_log "Next: Run \`zopp join <invite-token> you@email.com\` to get started."
    zopp_log "Docs: https://zopp.dev/quickstart"
    zopp_log ""
}

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --no-color) NO_COLOR=1 ;;
    esac
done

zopp_install
