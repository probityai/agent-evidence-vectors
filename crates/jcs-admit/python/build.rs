//! Reads the exact release of each bound crate out of `Cargo.toml`, so the version the
//! extension reports is the version it was built against and cannot be edited apart from
//! the pin. Cargo gives a build no version for a dependency, only for the package itself.

use std::{env, fs, path::Path};

/// The `=x.y.z` pin of dependency `name`, read from the `[dependencies]` text.
fn pinned_version(manifest: &str, name: &str) -> Result<String, String> {
    let prefix = format!("{name} = ");
    let line = manifest
        .lines()
        .find(|l| l.starts_with(&prefix))
        .ok_or_else(|| format!("Cargo.toml has no `{name}` dependency line"))?;
    let after = line
        .split("version = \"=")
        .nth(1)
        .ok_or_else(|| format!("`{name}` is not pinned with an exact `=` version"))?;
    let version = after
        .split('"')
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("`{name}` has an empty version"))?;
    Ok(version.to_owned())
}

fn main() -> Result<(), String> {
    let dir = env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?;
    let manifest_path = Path::new(&dir).join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    for (name, var) in [("jcs-admit", "JCS_ADMIT_BOUND_VERSION"), ("dsse", "DSSE_BOUND_VERSION")] {
        println!("cargo:rustc-env={var}={}", pinned_version(&manifest, name)?);
    }
    println!("cargo:rerun-if-changed=Cargo.toml");
    Ok(())
}
