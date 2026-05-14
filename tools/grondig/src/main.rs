// SPDX-License-Identifier: GPL-2.0-only
//
// grondig - report unfixed CVEs for Linux kernel SBOMs.
//
// Reads a JSON request from stdin and writes a JSON reply to stdout.
//
// Request format:
//   {
//     "<uid>": {
//       "stable-tag": "v6.12.5",
//       "cherry-picked": ["<sha>", ...],
//       "compiled-files": ["<path>", ...]
//     },
//     ...
//   }
//
// Reply format:
//   { "<uid>": { "cves": ["CVE-XXXX-YYYY", ...] }, ... }
//
// "grondig" means "thorough" in Dutch.
//
// Copyright (c) 2026 - Jorge Marques <jorge.marques@analog.com>

use anyhow::{anyhow, Result};
use clap::Parser;
use cve_utils::compare_kernel_versions;
use cve_utils::kernel_version_major;
use cve_utils::version_is_mainline;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Report CVEs that remain unfixed in a kernel version, accounting for cherry-picked fixes.
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// Path to post.db (default: <vulns-root>/post.db)
    #[clap(long)]
    post_db: Option<PathBuf>,

    /// Path to verhaal.db (default: <vulns-root>/tools/verhaal/verhaal.db)
    #[clap(long)]
    verhaal_db: Option<PathBuf>,
}

#[derive(Deserialize)]
struct SbomEntry {
    #[serde(rename = "stable-tag")]
    stable_tag: String,
    #[serde(rename = "cherry-picked", default)]
    cherry_picked: Vec<String>,
    #[serde(rename = "compiled-files", default)]
    compiled_files: Vec<String>,
}

#[derive(Serialize)]
struct CveResult {
    cves: Vec<String>,
}

struct PostDb {
    conn: Connection,
}

impl PostDb {
    fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(anyhow!("post.db not found at {}", path.display()));
        }
        Ok(Self { conn: Connection::open(path)? })
    }

    /// Returns all distinct CVEs that have SHA entries.
    fn all_cves(&self) -> Vec<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT cve FROM sha ORDER BY cve")
            .expect("prepare all_cves");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query all_cves")
            .flatten()
            .collect()
    }

    /// Returns SHAs for a CVE with the given role (1=fix, 0=vuln).
    fn shas_for(&self, cve: &str, role: i32) -> Vec<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT sha FROM sha WHERE cve=?1 AND role=?2")
            .expect("prepare shas_for");
        stmt.query_map(rusqlite::params![cve, role], |row| row.get::<_, String>(0))
            .expect("query shas_for")
            .flatten()
            .collect()
    }

    /// Returns true if this CVE has any file entries in the files table.
    fn cve_has_any_files(&self, cve: &str) -> bool {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE cve=?1",
                [cve],
                |row| row.get(0),
            )
            .unwrap_or(0);
        count > 0
    }

    /// Returns true if any file for this CVE is in `compiled_files`.
    fn cve_matches_files(&self, cve: &str, compiled_files: &HashSet<&str>) -> bool {
        let mut stmt = self
            .conn
            .prepare("SELECT file FROM files WHERE cve=?1")
            .expect("prepare cve_matches_files");
        stmt.query_map([cve], |row| row.get::<_, String>(0))
            .expect("query cve_matches_files")
            .flatten()
            .any(|f| compiled_files.contains(f.as_str()))
    }
}

/// Returns the kernel release version for a SHA from verhaal.db, or "" if not found.
fn get_version(conn: &Connection, sha: &str) -> String {
    conn.query_row(
        "SELECT release FROM commits WHERE id=?1",
        [sha],
        |row| row.get::<_, String>(0),
    )
    .unwrap_or_default()
}

/// Returns the mainline commit id for a given sha using verhaal.db.
/// For stable backports returns the mainline_id column; otherwise returns sha as-is.
fn get_mainline_id(conn: &Connection, sha: &str) -> String {
    conn.query_row(
        "SELECT COALESCE(NULLIF(mainline_id, ''), id) FROM commits WHERE id LIKE ?1 || '%'",
        [sha],
        |row| row.get::<_, String>(0),
    )
    .unwrap_or_else(|_| sha.to_string())
}

/// Returns true if `candidate` version is reachable from `target`.
/// "0" means no fix available.
fn version_reachable(candidate: &str, target: &str) -> bool {
    if candidate.is_empty() || candidate == "0" {
        return true; // unknown origin -> assume affects all versions
    }
    if version_is_mainline(candidate) {
        compare_kernel_versions(candidate, target) != std::cmp::Ordering::Greater
    } else {
        kernel_version_major(candidate) == kernel_version_major(target)
            && compare_kernel_versions(candidate, target) != std::cmp::Ordering::Greater
    }
}

/// Returns true if `sha` matches any cherry-pick.
fn sha_matches(sha: &str, cherry_picks: &HashSet<String>) -> bool {
    cherry_picks.contains(sha)
}

/// Expands raw cherry-pick SHAs to also include their mainline equivalents.
fn expand_cherry_picks(raw: &[String], verhaal: &Connection) -> HashSet<String> {
    let mut set = HashSet::new();
    for sha in raw {
        let lower = sha.to_lowercase();
        let mainline = get_mainline_id(verhaal, &lower);
        set.insert(lower);
        set.insert(mainline);
    }
    set
}

/// Returns true if the CVE is unfixed in `target` accounting for `cherry_picks`.
fn is_cve_unfixed(
    post_db: &PostDb,
    verhaal: &Connection,
    cve: &str,
    target: &str,
    cherry_picks: &HashSet<String>,
) -> bool {
    let vuln_shas = post_db.shas_for(cve, 0);
    let fix_shas = post_db.shas_for(cve, 1);

    // Determine if this CVE was introduced in or before `target`.
    let affected = if vuln_shas.is_empty() {
        true // no vulnerability-intro info -> assume affects all versions
    } else {
        vuln_shas
            .iter()
            .any(|sha| version_reachable(&get_version(verhaal, sha), target))
    };

    if !affected {
        return false;
    }

    // Check if any fix is included in the target or matches a cherry-pick.
    let fixed = fix_shas.iter().any(|sha| {
        version_reachable(&get_version(verhaal, sha), target) || sha_matches(sha, cherry_picks)
    });

    !fixed
}

/// Compute the list of unfixed CVEs for one SBOM entry.
fn compute_cves(
    post_db: &PostDb,
    verhaal: &Connection,
    stable_tag: &str,
    cherry_picked: &[String],
    compiled_files: &[String],
) -> Vec<String> {
    let target = stable_tag.strip_prefix('v').unwrap_or(stable_tag);
    let cherry_picks = expand_cherry_picks(cherry_picked, verhaal);
    let files_set: HashSet<&str> = compiled_files.iter().map(String::as_str).collect();

    post_db
        .all_cves()
        .into_iter()
        .filter(|cve| is_cve_unfixed(post_db, verhaal, cve, target, &cherry_picks))
        .filter(|cve| {
            // When compiled-files are given, skip CVEs whose file list is known
            // but doesn't overlap with compiled-files.
            if files_set.is_empty() {
                return true;
            }
            if !post_db.cve_has_any_files(cve) {
                return true;
            }
            post_db.cve_matches_files(cve, &files_set)
        })
        .collect()
}

fn find_post_db() -> Result<PathBuf> {
    let vulns_dir = cve_utils::common::find_vulns_dir()?;
    let p = vulns_dir.join("post.db");
    if p.exists() {
        Ok(p)
    } else {
        Err(anyhow!("post.db not found at {}", p.display()))
    }
}

fn find_verhaal_db() -> Result<PathBuf> {
    let vulns_dir = cve_utils::common::find_vulns_dir()?;
    let p = vulns_dir.join("tools").join("verhaal").join("verhaal.db");
    if p.exists() {
        Ok(p)
    } else {
        Err(anyhow!("verhaal.db not found at {}", p.display()))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read JSON request from stdin.
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: HashMap<String, SbomEntry> = serde_json::from_str(&input)
        .map_err(|e| anyhow!("invalid JSON input: {e}"))?;

    let post_db_path = match args.post_db {
        Some(p) => p,
        None => find_post_db()?,
    };
    let post_db = PostDb::open(&post_db_path)?;

    let verhaal_path = match args.verhaal_db {
        Some(p) => p,
        None => find_verhaal_db()?,
    };
    if !verhaal_path.exists() {
        return Err(anyhow!("verhaal.db not found at {}", verhaal_path.display()));
    }
    let verhaal = Connection::open(&verhaal_path)?;

    // Process each SBOM entry and build the reply.
    let mut reply: HashMap<String, CveResult> = HashMap::new();
    for (uid, entry) in &request {
        let cves = compute_cves(
            &post_db,
            &verhaal,
            &entry.stable_tag,
            &entry.cherry_picked,
            &entry.compiled_files,
        );
        reply.insert(uid.clone(), CveResult { cves });
    }

    println!("{}", serde_json::to_string_pretty(&reply)?);
    Ok(())
}
