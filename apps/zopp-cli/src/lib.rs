//! Zopp CLI library
//!
//! This library provides the core functionality for the zopp CLI,
//! allowing it to be tested independently from the binary.

pub mod cli;
pub mod client;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod grpc;
pub mod k8s;

// Re-export commonly used items for convenience
pub use config::{resolve_context, resolve_workspace, resolve_workspace_project, PrincipalConfig};
