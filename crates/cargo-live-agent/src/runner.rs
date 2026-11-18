//! `cargo-live-agent __runner <exe> [args...]`
//!
//! Configured as Cargo's `target.<host>.runner` for remote `cargo run`, so
//! Cargo itself selects the package, binary and features. Instead of running
//! the program it records what Cargo would have run and exits successfully.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const OUT_ENV: &str = "CARGO_LIVE_RUNNER_OUT";

#[derive(Debug, Serialize, Deserialize)]
pub struct RunnerOutput {
    pub executable: String,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
}

pub fn main(args: Vec<OsString>) -> i32 {
    match run(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cargo-live-agent __runner: {e}");
            1
        }
    }
}

fn run(args: Vec<OsString>) -> crate::Result<()> {
    let out = env::var_os(OUT_ENV).ok_or("this command is only used by cargo-live-agent")?;
    let executable = args.first().ok_or("missing executable")?;
    let cwd = env::current_dir()?;
    let mut executable = PathBuf::from(executable);
    if executable.is_relative() {
        executable = cwd.join(executable);
    }
    let env = env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .filter(|(k, _)| k.starts_with("CARGO_") || k == "CARGO")
        .collect();
    let output = RunnerOutput {
        executable: executable
            .into_os_string()
            .into_string()
            .map_err(|_| "executable path is not UTF-8")?,
        cwd: cwd.to_string_lossy().into_owned(),
        env,
    };
    std::fs::write(out, serde_json::to_vec(&output)?)?;
    Ok(())
}
