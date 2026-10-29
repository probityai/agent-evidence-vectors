// Captures the rustc that actually compiled this binary, so runtime_version in
// the report is the compiler that produced the result rather than whatever
// happens to be on PATH when it runs.
use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CROSSRUN_RUSTC_VERSION={}", version);
    println!("cargo:rerun-if-changed=build.rs");
}
