// SPDX-License-Identifier: GPL-2.0-only
//
// grondig CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("grondig"));
}

// CVE-2024-46869: vuln 6.10, fixed in 6.12 (7ffaa200251871980af12e57649ad57c70bf0f43)
// At v6.12 the mainline fix is included → not vulnerable.
#[test]
fn cve_fixed_in_base_version_not_reported() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.12")
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46869").not());
}

// CVE-2024-43884: vuln 4.3, mainline fix in 6.11 (538fd3921a...)
// At v6.12 the fix (6.11) is already <= 6.12 → not vulnerable.
#[test]
fn cve_fixed_before_base_version_not_reported() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.12")
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-43884").not());
}

// Any version query should produce a summary line.
#[test]
fn output_contains_total_line() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.12")
        .assert()
        .success()
        .stdout(predicate::str::contains("Total unfixed CVEs"));
}

// Passing the mainline fix SHA via --cherry-picked should mark the CVE as fixed.
// CVE-2024-46869 mainline fix: 7ffaa200251871980af12e57649ad57c70bf0f43 (6.12)
// For v6.11 the fix is not yet included, but providing the SHA fixes it.
#[test]
fn cherry_pick_fixes_cve() {
    let fix_sha = "7ffaa200251871980af12e57649ad57c70bf0f43";
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.11")
        .arg("--cherry-picked")
        .arg(fix_sha)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46869").not());
}

// Without the cherry-pick, CVE-2024-46869 should be vulnerable at v6.11.
#[test]
fn without_cherry_pick_cve_is_vulnerable() {
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.11")
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46869"));
}

// A short (12-char) SHA prefix should also work for cherry-pick matching.
#[test]
fn cherry_pick_short_sha_works() {
    // First 12 chars of 7ffaa200251871980af12e57649ad57c70bf0f43
    let short_sha = "7ffaa2002518";
    let mut cmd = Command::new(cargo::cargo_bin!("grondig"));

    cmd.arg("v6.11")
        .arg("--cherry-picked")
        .arg(short_sha)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46869").not());
}
