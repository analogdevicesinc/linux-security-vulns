// SPDX-License-Identifier: GPL-2.0-only
//
// grondig gRPC tests
// Requires post.db

use assert_cmd::Command as Cmd;
use predicates::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Proto types — re-generated from the same proto the binary uses.
// ---------------------------------------------------------------------------

pub mod fnv1 {
    include!(concat!(env!("OUT_DIR"), "/apiextensions.r#fn.proto.v1.rs"));
}

use fnv1::function_runner_service_client::FunctionRunnerServiceClient;
use fnv1::{RunFunctionRequest, RequestMeta, State, Resource};
use prost_types::value::Kind;
use prost_types::{Struct, Value as PbValue, ListValue};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Root of the vulns repository (two levels up from tools/grondig/).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

/// Path to post.db.
fn post_db() -> PathBuf {
    repo_root().join("post.db")
}

fn pb_string(s: &str) -> PbValue {
    PbValue { kind: Some(Kind::StringValue(s.into())) }
}

fn pb_list(items: &[&str]) -> PbValue {
    PbValue {
        kind: Some(Kind::ListValue(ListValue {
            values: items.iter().map(|s| pb_string(s)).collect(),
        })),
    }
}

fn pb_list_owned(items: &[String]) -> PbValue {
    PbValue {
        kind: Some(Kind::ListValue(ListValue {
            values: items.iter().map(|s| pb_string(s)).collect(),
        })),
    }
}

/// Build a RunFunctionRequest with the given SBOM spec fields.
fn make_request(
    stable_tag: &str,
    cherry_picked: &[&str],
    compiled_files: &[&str],
) -> RunFunctionRequest {
    let mut spec_fields = BTreeMap::new();
    spec_fields.insert("stableTag".into(), pb_string(stable_tag));
    spec_fields.insert("cherryPicked".into(), pb_list(cherry_picked));
    spec_fields.insert("compiledFiles".into(), pb_list(compiled_files));

    let mut resource_fields = BTreeMap::new();
    resource_fields.insert("spec".into(), PbValue {
        kind: Some(Kind::StructValue(Struct { fields: spec_fields })),
    });

    RunFunctionRequest {
        meta: Some(RequestMeta { tag: "test".into(), ..Default::default() }),
        observed: Some(State {
            composite: Some(Resource {
                resource: Some(Struct { fields: resource_fields }),
                ..Default::default()
            }),
            resources: Default::default(),
        }),
        ..Default::default()
    }
}

fn make_request_owned(
    stable_tag: &str,
    cherry_picked: &[&str],
    compiled_files: &[String],
) -> RunFunctionRequest {
    let mut spec_fields = BTreeMap::new();
    spec_fields.insert("stableTag".into(), pb_string(stable_tag));
    spec_fields.insert("cherryPicked".into(), pb_list(cherry_picked));
    spec_fields.insert("compiledFiles".into(), pb_list_owned(compiled_files));

    let mut resource_fields = BTreeMap::new();
    resource_fields.insert("spec".into(), PbValue {
        kind: Some(Kind::StructValue(Struct { fields: spec_fields })),
    });

    RunFunctionRequest {
        meta: Some(RequestMeta { tag: "test".into(), ..Default::default() }),
        observed: Some(State {
            composite: Some(Resource {
                resource: Some(Struct { fields: resource_fields }),
                ..Default::default()
            }),
            resources: Default::default(),
        }),
        ..Default::default()
    }
}

/// Extract the CVE list from the response context "grondig/cves".
fn extract_cves(resp: &fnv1::RunFunctionResponse) -> Vec<String> {
    resp.context
        .as_ref()
        .and_then(|ctx| ctx.fields.get("grondig/cves"))
        .and_then(|v| match &v.kind {
            Some(Kind::ListValue(lv)) => Some(lv),
            _ => None,
        })
        .map(|lv| {
            lv.values.iter()
                .filter_map(|v| match &v.kind {
                    Some(Kind::StringValue(s)) => Some(s.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Find an available TCP port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Spawn the grondig gRPC server on the given port, wait for it to be ready.
fn spawn_server(port: u16) -> Child {
    let bin = assert_cmd::cargo::cargo_bin("grondig");
    let child = Command::new(bin)
        .args([
            "--insecure",
            "--address", &format!("127.0.0.1:{port}"),
            "--post-db", &post_db().to_string_lossy(),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn grondig");

    // Wait for the server to be listening.
    for _ in 0..50 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("grondig server did not start on port {port}");
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn connect(port: u16) -> FunctionRunnerServiceClient<tonic::transport::Channel> {
    FunctionRunnerServiceClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .expect("connect to grondig")
}

/// Call RunFunction and return the CVE list.
async fn cves_for(port: u16, stable_tag: &str, cherry_picked: &[&str], compiled_files: &[&str]) -> Vec<String> {
    let mut client = connect(port).await;
    let resp = client.run_function(make_request(stable_tag, cherry_picked, compiled_files))
        .await
        .expect("RunFunction")
        .into_inner();
    let mut cves = extract_cves(&resp);
    cves.sort();
    cves
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn help_flag_shows_usage() {
    Cmd::cargo_bin("grondig")
        .expect("grondig binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("grondig"));
}

#[tokio::test]
async fn missing_spec_returns_fatal() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let mut client = connect(port).await;

    let req = RunFunctionRequest {
        meta: Some(RequestMeta { tag: "test".into(), ..Default::default() }),
        observed: Some(State {
            composite: Some(Resource {
                resource: Some(Struct { fields: BTreeMap::new() }),
                ..Default::default()
            }),
            resources: Default::default(),
        }),
        ..Default::default()
    };

    let resp = client.run_function(req).await.unwrap().into_inner();
    assert_eq!(resp.results[0].severity, fnv1::Severity::Fatal as i32);
    assert!(resp.results[0].message.contains("no spec"));
}

#[tokio::test]
async fn missing_stable_tag_returns_fatal() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let mut client = connect(port).await;

    let mut spec_fields = BTreeMap::new();
    spec_fields.insert("cherryPicked".into(), pb_list(&[]));
    let mut resource_fields = BTreeMap::new();
    resource_fields.insert("spec".into(), PbValue {
        kind: Some(Kind::StructValue(Struct { fields: spec_fields })),
    });

    let req = RunFunctionRequest {
        meta: Some(RequestMeta { tag: "test".into(), ..Default::default() }),
        observed: Some(State {
            composite: Some(Resource {
                resource: Some(Struct { fields: resource_fields }),
                ..Default::default()
            }),
            resources: Default::default(),
        }),
        ..Default::default()
    };

    let resp = client.run_function(req).await.unwrap().into_inner();
    assert_eq!(resp.results[0].severity, fnv1::Severity::Fatal as i32);
    assert!(resp.results[0].message.contains("stableTag"));
}

// CVE-2024-46869: introduced in 6.10, fixed in 6.12 (7ffaa200251871980af12e57649ad57c70bf0f43)
// At v6.12 the mainline fix is included → not vulnerable.
#[tokio::test]
async fn cve_fixed_in_base_version_not_reported() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.12", &[], &[]).await;
    assert!(
        !cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be fixed at v6.12"
    );
}

// CVE-2024-43884: introduced in 4.3, mainline fix in 6.11 (538fd3921a…).
// At v6.12 the fix (6.11) precedes 6.12 → not vulnerable.
#[tokio::test]
async fn cve_fixed_before_base_version_not_reported() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.12", &[], &[]).await;
    assert!(
        !cves.contains(&"CVE-2024-43884".to_string()),
        "CVE-2024-43884 should be fixed at v6.12"
    );
}

// CVE-2024-46869 is not yet fixed at v6.11 (fix arrived in 6.12).
#[tokio::test]
async fn cve_unfixed_in_earlier_version() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.11", &[], &[]).await;
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be unfixed at v6.11"
    );
}

// Response includes a Normal result and GrondigReady condition.
#[tokio::test]
async fn response_has_result_and_condition() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let mut client = connect(port).await;

    let resp = client.run_function(make_request("v6.12", &[], &[]))
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.results.is_empty(), "should have at least one result");
    assert_eq!(resp.results[0].severity, fnv1::Severity::Normal as i32);
    assert!(resp.results[0].message.contains("grondig:"));

    assert!(!resp.conditions.is_empty(), "should have at least one condition");
    assert_eq!(resp.conditions[0].r#type, "GrondigReady");
}

// Providing the mainline fix SHA for CVE-2024-46869 via cherry-picked should
// mark it as fixed even at v6.11.
#[tokio::test]
async fn cherry_pick_fixes_cve() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let fix_sha = "7ffaa200251871980af12e57649ad57c70bf0f43";
    let cves = cves_for(port, "v6.11", &[fix_sha], &[]).await;
    assert!(
        !cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be fixed by cherry-pick at v6.11"
    );
}

// Without the cherry-pick, CVE-2024-46869 must still appear at v6.11.
#[tokio::test]
async fn without_cherry_pick_cve_is_vulnerable() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.11", &[], &[]).await;
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be unfixed at v6.11 without cherry-pick"
    );
}

// CVE-2024-46869 affects drivers/bluetooth/btintel_pcie.c.
// Passing that file should keep the CVE in the unfixed list for v6.11.
#[tokio::test]
async fn file_filter_keeps_matching_cve() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.11", &[], &["drivers/bluetooth/btintel_pcie.c"]).await;
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should appear when its affected file is in compiled-files"
    );
}

// Passing an unrelated file should exclude CVE-2024-46869 (its file doesn't match).
#[tokio::test]
async fn file_filter_excludes_non_matching_cve() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };
    let cves = cves_for(port, "v6.11", &[], &["scripts/dtc/fdtoverlay.c"]).await;
    assert!(
        !cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be excluded when compiled-files don't include its file"
    );
}

/// Parse compiled source files from the test SBOM fixture.
fn sbom_source_files() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sbom.json");
    let data: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    data["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| {
            item["type"].as_str() == Some("software_File")
                && item["spdxId"]
                    .as_str()
                    .map(|s| s.contains("/file/src/"))
                    .unwrap_or(false)
        })
        .map(|item| item["name"].as_str().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// Full chain: SBOM-derived compiled files + stable tag + cherry-picks.
#[tokio::test]
async fn full_sbom_chain_returns_valid_cve_list() {
    let port = free_port();
    let _guard = ServerGuard { child: spawn_server(port) };

    let files = sbom_source_files();
    assert!(!files.is_empty(), "SBOM must have source files");

    let cherry_picked = ["ef9a45f7f148b319f8ed7c4e2ff9f3d7c914cb3f"];
    let mut client = connect(port).await;

    let resp = client.run_function(make_request_owned("v6.12.5", &cherry_picked, &files))
        .await
        .unwrap()
        .into_inner();

    let cves = extract_cves(&resp);
    let unfiltered = cves_for(port, "v6.12.5", &[], &[]).await;

    // The filtered list must be a subset of the unfiltered list.
    for cve in &cves {
        assert!(
            unfiltered.contains(cve),
            "{cve} in filtered list but not in unfiltered list"
        );
    }
    assert!(
        cves.len() <= unfiltered.len(),
        "filtered ({}) must be <= unfiltered ({})",
        cves.len(),
        unfiltered.len()
    );
}
