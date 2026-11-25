//! Find Evil! MCP server binary.
//!
//! Spec #2 §2 + §3 + Amendment A2. Stdio transport for the MCP server.
//!
//! Argument handling:
//!   * `--version` / `-V` — print version and exit.
//!   * `--help` / `-h`    — print usage and exit.
//!   * (no args)          — run the stdio JSON-RPC server until stdin closes.
//!
//! Logs go to stderr. Stdout is the JSON-RPC channel — anything that
//! is not a valid response line corrupts the protocol stream.

#![forbid(unsafe_code)]

use std::env;

use findevil_mcp::{server, CRATE_VERSION};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = env::args().collect();

    // Configure logging to stderr ONLY. Stdout is the JSON-RPC wire.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("findevil-mcp {CRATE_VERSION}");
        return std::process::ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "findevil-mcp {CRATE_VERSION}\n\
             \n\
             Usage: findevil-mcp [OPTIONS]\n\
             \n\
             Options:\n\
               --version, -V   Print version and exit\n\
               --help, -h      Print this help\n\
             \n\
             Without arguments, runs the MCP stdio JSON-RPC server until\n\
             stdin closes. Speaks MCP 2024-11-05 over line-delimited JSON.\n\
             Logs to stderr; stdout is the protocol channel.\n"
        );
        return std::process::ExitCode::SUCCESS;
    }

    tracing::info!(
        target = "findevil_mcp",
        "findevil-mcp {CRATE_VERSION} starting stdio server"
    );

    match server::run_stdio_server() {
        Ok(()) => {
            tracing::info!(target = "findevil_mcp", "stdio server exited cleanly");
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(target = "findevil_mcp", "stdio server I/O error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
