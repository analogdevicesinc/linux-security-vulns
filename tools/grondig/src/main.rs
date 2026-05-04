// SPDX-License-Identifier: GPL-2.0-only
//
// grondig - report unfixed CVEs for a kernel version, optionally accounting
// for cherry-picked fix commits.  No kernel git tree required.
//
// "grondig" means "thorough" in Dutch.
//
// Copyright (c) 2026 - Jorge Marques <jorge.marques@analog.com>

use anyhow::{anyhow, Result};
use clap::Parser;
use cve_utils::common;
use cve_utils::compare_kernel_versions;
use cve_utils::dyad::DyadEntry;
use cve_utils::kernel_version_major;
use cve_utils::version_is_mainline;
use cve_utils::Verhaal;
use log::{debug, error};
use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Report CVEs that remain unfixed in a kernel version, accounting for cherry-picked fixes.
///   grondig v6.12 --cherry-picked abc123 def456
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// Kernel version to check (e.g. v6.12 or 6.12)
    kernel_version: String,

    /// Cherry-picked fix commit SHAs
    #[clap(long)]
    cherry_picked: Vec<String>,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

/// Read all .dyad files under `dir` recursively.
/// Returns (cve_name, Vec<DyadEntry>) pairs.
fn read_dyads(dir: &Path) -> Result<Vec<(String, Vec<DyadEntry>)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            out.append(&mut read_dyads(&entry.path())?);
        } else if ft.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(cve) = name.strip_suffix(".dyad") {
                let content = fs::read_to_string(entry.path())?;
                let entries: Vec<DyadEntry> = content
                    .lines()
                    .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                    .filter_map(|l| DyadEntry::new_no_validate(l).ok())
                    .collect();
                out.push((cve.to_string(), entries));
            }
        }
    }
    Ok(out)
}

/// Is candidate version reachable from target version?
fn version_reachable(candidate: &str, target: &str) -> bool {
    if version_is_mainline(candidate) {
        compare_kernel_versions(candidate, target) != std::cmp::Ordering::Greater
    } else {
        kernel_version_major(candidate) == kernel_version_major(target)
            && compare_kernel_versions(candidate, target) != std::cmp::Ordering::Greater
    }
}

/// Check whether a dyad SHA matches any cherry-pick (prefix match both ways).
fn sha_matches(sha: &str, cherry_picks: &HashSet<String>) -> bool {
    cherry_picks.iter().any(|cp| sha.starts_with(cp.as_str()) || cp.starts_with(sha))
}

/// Expand cherry-picked SHAs: resolve backport->mainline via verhaal.db.
fn expand_cherry_picks(raw: &[String], verhaal: &Verhaal) -> HashSet<String> {
    let mut set = HashSet::new();
    for sha in raw {
        let lower = sha.to_lowercase();
        let mainline = verhaal.get_mainline_id(&lower);
        debug!("cherry-pick {}: mainline={}", &lower[..12.min(lower.len())], &mainline[..12.min(mainline.len())]);
        set.insert(lower);
        set.insert(mainline);
    }
    set
}

/// Returns true if CVE is unfixed in target given cherry_picks.
fn is_unfixed(entries: &[DyadEntry], target: &str, cherry_picks: &HashSet<String>) -> bool {
    let mut affected = false;

    for e in entries {
        let vuln_present = e.vulnerable.is_empty()
            || version_reachable(&e.vulnerable.version(), target);
        if !vuln_present {
            continue;
        }
        affected = true;

        if e.fixed.is_empty() {
            continue;
        }

        // Fixed in base version or by cherry-pick?
        if version_reachable(&e.fixed.version(), target)
            || sha_matches(&e.fixed.git_id(), cherry_picks)
        {
            return false;
        }
    }

    affected
}

fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.verbose { log::LevelFilter::max() } else { log::LevelFilter::Error };
    env_logger::builder().format_timestamp(None).filter_level(level).init();

    let target = args.kernel_version.strip_prefix('v').unwrap_or(&args.kernel_version);

    let published = common::find_vulns_dir()?.join("cve").join("published");
    let dyads = read_dyads(&published).map_err(|e| { error!("{e}"); anyhow!("{e}") })?;
    debug!("Loaded {} CVE ids", dyads.len());

    let cherry_picks = if args.cherry_picked.is_empty() {
        HashSet::new()
    } else {
        expand_cherry_picks(&args.cherry_picked, &Verhaal::new()?)
    };

    let mut count = 0u32;
    for (cve, entries) in &dyads {
        if is_unfixed(entries, target, &cherry_picks) {
            println!(
                "{} is vulnerable to {}",
                target.if_supports_color(Stdout, |x| x.green()),
                cve.if_supports_color(Stdout, |x| x.red()),
            );
            count += 1;
        }
    }

    println!(
        "\nTotal unfixed CVEs in {}: {}",
        target.if_supports_color(Stdout, |x| x.green()),
        count.to_string().if_supports_color(Stdout, |x| x.red()),
    );

    Ok(())
}
