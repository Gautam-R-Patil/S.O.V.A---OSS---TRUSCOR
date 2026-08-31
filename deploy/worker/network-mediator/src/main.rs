// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sova_network_mediator::{parse_policy, serve, ReceiptRecorder};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

struct Args {
    policy_file: PathBuf,
    listen: String,
    receipt_directory: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut values = env::args_os().skip(1);
    let mut policy_file = None;
    let mut listen = None;
    let mut receipt_directory = None;
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--policy-file") if policy_file.is_none() => policy_file = Some(value.into()),
            Some("--listen") if listen.is_none() => {
                listen = Some(
                    value
                        .into_string()
                        .map_err(|_| "--listen must be UTF-8".to_owned())?,
                );
            }
            Some("--receipt-directory") if receipt_directory.is_none() => {
                receipt_directory = Some(value.into());
            }
            Some(other) => return Err(format!("unknown or duplicate argument: {other}")),
            None => return Err("argument name must be UTF-8".to_owned()),
        }
    }
    Ok(Args {
        policy_file: policy_file.ok_or("--policy-file is required")?,
        listen: listen.ok_or("--listen is required")?,
        receipt_directory: receipt_directory.ok_or("--receipt-directory is required")?,
    })
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect policy file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("policy path must be a regular non-symlink file".to_owned());
    }
    if metadata.len() > MAX_POLICY_BYTES {
        return Err("policy file exceeds 1 MiB".to_owned());
    }
    fs::read(path).map_err(|error| format!("cannot read policy file: {error}"))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let raw = read_regular_file(&args.policy_file)?;
    let policy = parse_policy(&raw)?;
    if args.listen != policy.listen_authority() {
        return Err("--listen does not match the content-addressed policy".to_owned());
    }
    let recorder = ReceiptRecorder::open(&args.receipt_directory, policy.job_id.clone())?;
    let listener = TcpListener::bind(&args.listen)
        .map_err(|error| format!("cannot bind the exact mediator listener: {error}"))?;
    serve(policy, &listener, recorder)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sova-network-mediator: {error}");
            ExitCode::FAILURE
        }
    }
}
