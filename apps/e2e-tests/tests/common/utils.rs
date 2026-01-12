//! Shared utilities for E2E tests.

use std::path::PathBuf;

/// Get binary paths (zopp-server, zopp, zopp-operator)
/// Works with both regular and llvm-cov target directories
pub fn get_binary_paths() -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    // Check for llvm-cov target directory first, then regular target
    let target_dir = std::env::var("CARGO_LLVM_COV_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| workspace_root.join("target").to_str().unwrap().to_string());

    // llvm-cov uses target/llvm-cov-target/debug, regular builds use target/debug
    let llvm_cov_bin_dir = PathBuf::from(&target_dir)
        .join("llvm-cov-target")
        .join("debug");
    let regular_bin_dir = PathBuf::from(&target_dir).join("debug");
    let bin_dir = if llvm_cov_bin_dir.exists() {
        llvm_cov_bin_dir
    } else {
        regular_bin_dir
    };

    let zopp_server_bin = bin_dir.join(if cfg!(windows) {
        "zopp-server.exe"
    } else {
        "zopp-server"
    });
    let zopp_bin = bin_dir.join(if cfg!(windows) { "zopp.exe" } else { "zopp" });
    let operator_bin = bin_dir.join(if cfg!(windows) {
        "zopp-operator.exe"
    } else {
        "zopp-operator"
    });

    if !zopp_server_bin.exists() || !zopp_bin.exists() {
        return Err(format!(
            "Binaries not found. Please run 'cargo build --bins' first.\n  Expected: {}\n  Expected: {}",
            zopp_server_bin.display(),
            zopp_bin.display()
        ).into());
    }

    Ok((zopp_server_bin, zopp_bin, operator_bin))
}

/// Gracefully shutdown a child process for coverage data collection.
/// Sends SIGTERM first, waits briefly, then falls back to SIGKILL.
#[cfg(unix)]
pub fn graceful_shutdown(child: &mut std::process::Child) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use std::time::Duration;

    let pid = Pid::from_raw(child.id() as i32);
    let _ = kill(pid, Signal::SIGTERM);

    // Wait up to 2 seconds for graceful shutdown
    for _ in 0..20 {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }

    // Force kill if still running
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
pub fn graceful_shutdown(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
