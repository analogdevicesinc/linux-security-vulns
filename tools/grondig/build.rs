// SPDX-License-Identifier: GPL-2.0-only
use std::path::PathBuf;

const PROTO_URL: &str = "https://raw.githubusercontent.com/crossplane/crossplane/main/proto/fn/v1/run_function.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let proto = out.join("run_function.proto");

    if !proto.exists() {
        let body = reqwest::blocking::get(PROTO_URL)?.error_for_status()?.bytes()?;
        std::fs::write(&proto, &body)?;
    }

    let include: PathBuf = "/usr/include".into();
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[&proto], &[&out, &include])?;

    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
