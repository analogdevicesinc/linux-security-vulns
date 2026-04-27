// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// strak CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("You must provide either a Git SHA or --fixed option"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dig in the CVE database"));
}

#[test]
fn fixed_with_known_version() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("--fixed")
        .arg("6.12.3")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE"));
}

#[test]
fn fixed_with_version_no_fixes() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    // Use a very old version unlikely to have fixes in the database
    cmd.arg("--fixed")
        .arg("0.0.1")
        .assert()
        .success()
        .stdout(predicate::str::contains("did not fix any CVE"));
}

#[test]
fn positional_arg_known_tag() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("v6.12.3")
        .assert()
        .success()
        .stdout(predicate::str::contains("vulnerable"));
}

#[test]
fn cve_tag_not_vulnerable() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg("v6.12")
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-43884").not());
}

// The cve_* tests are against the live tree and may silently change the expected result
// if the referenced CVE's dyad changes. In the case of suddenly breakage, verify if
// the expected result still stands through git:
//   git merge-base --is-ancestor <fix> <target> ; echo $?
// and look at the dyad history, before inspecting the codebase.

// CVE-2024-46869: vulnerable 6.10 (6e65a09f92) -> 6.12 (7ffaa20025)
#[test]
fn cve_tag_not_vulnerable_fix_in_major_release() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));
    cmd.arg("v6.12")
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46869").not());
}

/// Commit based on v6.11-rc2, merged into v6.12.
const TOPIC_BRANCH_COMMIT: &str = "bbf3c7ff9dfa45be51500d23a1276991a7cd8c6e";

/// CVE-2024-43884: vulnerable v4.3->v6.11-rc5
#[test]
fn cve_fix_not_in_history() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg(TOPIC_BRANCH_COMMIT)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-43884"));
}

/// CVE-2024-46823: vulnerable v6.8->v6.11-rc4
#[test]
fn cve_fix_not_in_history_2() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg(TOPIC_BRANCH_COMMIT)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-46823"));
}

/// CVE-2024-26600: vulnerable v3.7->v6.8.
#[test]
fn cve_fix_in_history() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg(TOPIC_BRANCH_COMMIT)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-26600").not());
}

/// CVE-2024-50084: vulnerable from v6.11-rc7
#[test]
fn cve_newer_than_commit() {
    let mut cmd = Command::new(cargo::cargo_bin!("strak"));

    cmd.arg(TOPIC_BRANCH_COMMIT)
        .assert()
        .success()
        .stdout(predicate::str::contains("is vulnerable to CVE-2024-50084").not());
}
