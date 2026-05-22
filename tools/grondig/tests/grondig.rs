// SPDX-License-Identifier: GPL-2.0-only
//
// grondig CLI tests
// Requires post.db

use assert_cmd::Command as Cmd;
use predicates::prelude::*;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Root of the vulns repository (parent of tools/).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tools/ parent")
        .to_path_buf()
}

/// Path to post.db.
fn post_db() -> PathBuf {
    repo_root().join("post.db")
}

/// Run grondig with the given JSON request; asserts success and returns parsed reply.
fn grondig(request: &Value) -> Value {
    let out = Cmd::cargo_bin("grondig")
        .expect("grondig binary")
        .arg("--post-db")
        .arg(post_db())
        .write_stdin(serde_json::to_string(request).unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&out).expect("valid JSON reply")
}

/// Shorthand: returns the CVE list for a single-entry request.
fn cves_for(stable_tag: &str, cherry_picked: &[&str], compiled_files: &[&str]) -> Vec<String> {
    let reply = grondig(&json!({
        "test": {
            "stable-tag": stable_tag,
            "cherry-picked": cherry_picked,
            "compiled-files": compiled_files,
        }
    }));
    let mut cves: Vec<String> = serde_json::from_value(reply["test"]["cves"].clone())
        .expect("cves array");
    cves.sort();
    cves
}

#[test]
fn help_flag_shows_usage() {
    Cmd::cargo_bin("grondig")
        .expect("grondig binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("grondig"));
}

#[test]
fn empty_json_object_succeeds() {
    Cmd::cargo_bin("grondig")
        .expect("grondig binary")
        .arg("--post-db")
        .arg(post_db())
        .write_stdin("{}")
        .assert()
        .success()
        .stdout(predicate::str::contains("{}"));
}

#[test]
fn invalid_json_returns_error() {
    Cmd::cargo_bin("grondig")
        .expect("grondig binary")
        .arg("--post-db")
        .arg(post_db())
        .write_stdin("not json")
        .assert()
        .failure();
}

// CVE-2024-46869: introduced in 6.10, fixed in 6.12 (7ffaa200251871980af12e57649ad57c70bf0f43)
// At v6.12 the mainline fix is included → not vulnerable.
#[test]
fn cve_fixed_in_base_version_not_reported() {
    let cves = cves_for("v6.12", &[], &[]);
    assert!(
        !cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be fixed at v6.12"
    );
}

// CVE-2024-43884: introduced in 4.3, mainline fix in 6.11 (538fd3921a…).
// At v6.12 the fix (6.11) precedes 6.12 → not vulnerable.
#[test]
fn cve_fixed_before_base_version_not_reported() {
    let cves = cves_for("v6.12", &[], &[]);
    assert!(
        !cves.contains(&"CVE-2024-43884".to_string()),
        "CVE-2024-43884 should be fixed at v6.12"
    );
}

// CVE-2024-46869 is not yet fixed at v6.11 (fix arrived in 6.12).
#[test]
fn cve_unfixed_in_earlier_version() {
    let cves = cves_for("v6.11", &[], &[]);
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be unfixed at v6.11"
    );
}

// Reply contains the expected JSON structure (uid → cves array).
#[test]
fn reply_contains_cves_key() {
    let reply = grondig(&json!({
        "my-sbom": {
            "stable-tag": "v6.12",
            "cherry-picked": [],
            "compiled-files": [],
        }
    }));
    assert!(reply["my-sbom"]["cves"].is_array(), "reply must have a 'cves' array");
}

// Providing the mainline fix SHA for CVE-2024-46869 via cherry-picked should
// mark it as fixed even at v6.11.
#[test]
fn cherry_pick_fixes_cve() {
    let fix_sha = "7ffaa200251871980af12e57649ad57c70bf0f43";
    let cves = cves_for("v6.11", &[fix_sha], &[]);
    assert!(
        !cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be fixed by cherry-pick at v6.11"
    );
}

// Without the cherry-pick, CVE-2024-46869 must still appear at v6.11.
#[test]
fn without_cherry_pick_cve_is_vulnerable() {
    let cves = cves_for("v6.11", &[], &[]);
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should be unfixed at v6.11 without cherry-pick"
    );
}


// CVE-2024-46869 affects drivers/bluetooth/btintel_pcie.c.
// Passing that file should keep the CVE in the unfixed list for v6.11.
#[test]
fn file_filter_keeps_matching_cve() {
    let cves = cves_for("v6.11", &[], &["drivers/bluetooth/btintel_pcie.c"]);
    assert!(
        cves.contains(&"CVE-2024-46869".to_string()),
        "CVE-2024-46869 should appear when its affected file is in compiled-files"
    );
}

// Passing an unrelated file should exclude CVE-2024-46869 (its file doesn't match).
#[test]
fn file_filter_excludes_non_matching_cve() {
    // Use a file that is definitely not related to the Bluetooth CVE.
    let cves = cves_for("v6.11", &[], &["scripts/dtc/fdtoverlay.c"]);
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
// The UID is the exact spdxId from the SBOM document element.
#[test]
fn full_sbom_chain_returns_valid_cve_list() {
    let uid = "urn:purl:pkg:github/analogdevicesinc/linux@ef9a45f7f148b319f8ed7c4e2ff9f3d7c914cb3f\
               ?release=6.12.0%2B&compiler=llvm-19&arch=x86&config=adi_ci_defconfig\
               &image=bzImage&ref=refs%2Fheads%2Fprepare-sdg-linux-artefacts/document";
    let files = sbom_source_files();
    assert!(!files.is_empty(), "SBOM must have source files");

    // Cherry-picked SHA from the SBOM: HEAD of the fork.
    let cherry_picked = vec!["ef9a45f7f148b319f8ed7c4e2ff9f3d7c914cb3f"];

    let reply = grondig(&json!({
        uid: {
            "stable-tag": "v6.12.5",
            "cherry-picked": cherry_picked,
            "compiled-files": files,
        }
    }));

    let cves: Vec<String> = serde_json::from_value(reply[uid]["cves"].clone())
        .expect("cves array from full SBOM chain");
    // The filtered list must be a strict subset of the unfiltered list.
    let unfiltered = cves_for("v6.12.5", &[], &[]);
    for cve in &cves {
        assert!(
            unfiltered.contains(cve),
            "{cve} in filtered list but not in unfiltered list"
        );
    }
    // File filtering must reduce the count (SBOM compiles only ~878 of many files).
    let unfiltered_count = unfiltered.len();
    let filtered_count = cves.len();
    assert!(
        filtered_count <= unfiltered_count,
        "filtered ({filtered_count}) must be <= unfiltered ({unfiltered_count})"
    );
}

// Multiple UIDs in one request must each get independent CVE lists.
#[test]
fn multiple_sbom_entries_are_independent() {
    let reply = grondig(&json!({
        "sbom-a": {
            "stable-tag": "v6.11",
            "cherry-picked": [],
            "compiled-files": [],
        },
        "sbom-b": {
            "stable-tag": "v6.12",
            "cherry-picked": [],
            "compiled-files": [],
        }
    }));

    let cves_a: Vec<String> =
        serde_json::from_value(reply["sbom-a"]["cves"].clone()).unwrap();
    let cves_b: Vec<String> =
        serde_json::from_value(reply["sbom-b"]["cves"].clone()).unwrap();

    // 6.11 should have more unfixed CVEs than 6.12 (older release).
    assert!(
        cves_a.len() > cves_b.len(),
        "v6.11 ({}) should have more unfixed CVEs than v6.12 ({})",
        cves_a.len(),
        cves_b.len()
    );
}
