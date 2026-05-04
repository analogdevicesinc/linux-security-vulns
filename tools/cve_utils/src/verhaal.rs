// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
//
// verhaal.rs - some common functions to help with digging information out of the verhaal database
//
//

use crate::common;
use crate::Kernel;
use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{Connection, ToSql};
use std::fs;
use std::sync::OnceLock;

/// Raw backport entry from the database, before policy filtering
#[derive(Debug, Clone)]
pub struct BackportEntry {
    /// The backport commit ID
    pub id: String,
    /// The kernel release version
    pub release: String,
    /// If this commit is a revert, the ID of what it reverts
    pub reverts: Option<String>,
    /// If this commit was reverted, the revert commit ID
    pub revert_id: Option<String>,
    /// If this commit was reverted, the revert commit release
    pub revert_release: Option<String>,
}

/// Result of found_in() containing both non-reverted backports and revert-based fixes
#[derive(Debug, Default)]
pub struct FoundInResult {
    /// Non-reverted backports (these are vulnerable or fixed depending on context)
    pub kernels: Vec<Kernel>,
    /// Pairs of (reverted_backport, revert_commit) - the revert is a fix for that branch
    pub reverted_pairs: Vec<(Kernel, Kernel)>,
}

// Location of the verhaal database we are working on.
static VERHAAL_DB: OnceLock<String> = OnceLock::new();

pub struct Verhaal {
    conn: Connection,
}

/// Generic SQL query function that can handle different return types and parameters
fn execute_query<T, P>(conn: &Connection, sql: &str, params: P) -> Vec<T>
where
    T: rusqlite::types::FromSql,
    P: rusqlite::Params,
{
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            debug!("SQL prepare error: {e:?} for query: {sql}");
            return vec![];
        }
    };

    let rows = match stmt.query(params) {
        Ok(r) => r,
        Err(e) => {
            debug!("SQL query error: {e:?} for query: {sql}");
            return vec![];
        }
    };

    rows.map(|row| row.get(0)).collect().unwrap_or_default()
}

/// Helper function that returns a vector of strings from a SQL query
fn query_strings(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> Vec<String> {
    execute_query(conn, sql, params)
}

/// Helper function that returns a vector of u32 from a SQL query
fn query_u32(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> Vec<u32> {
    execute_query(conn, sql, params)
}

/// Helper function that returns a single string from a SQL query, empty string if not found
fn query_string(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> String {
    let results: Vec<String> = execute_query(conn, sql, params);
    results.first().cloned().unwrap_or_default()
}

impl Verhaal {
    /// Create a new Verhaal object
    /// Will attempt to open a database connection with the file given
    ///
    /// # Errors
    ///
    /// Returns an error if the verhaal database cannot be opened or accessed
    pub fn new() -> Result<Self> {
        // Attempt to open the database connection
        let conn = Connection::open(Self::verhaal_database_file())?;

        Ok(Self { conn })
    }

    /// Returns the kernel version that this git sha is in
    /// If this is an invalid git sha, an error is returned
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git SHA is not found in the database
    /// - The database query fails
    pub fn get_version(&self, git_sha: &str) -> Result<String> {
        // Use our generic query function
        let versions = query_strings(
            &self.conn,
            "SELECT release from commits WHERE id=?1",
            &[&git_sha as &dyn ToSql],
        );

        if let Some(version) = versions.first() {
            debug!("\t\tget_version: '{git_sha}' => '{version:?}'");
            return Ok(version.clone());
        }

        debug!("\t\tget_version: '{git_sha}' => VERSION NOT FOUND");
        Err(anyhow!("Version {git_sha} not found"))
    }

    /// Returns a vector of kernels that are fixes for this specific git id as listed in the database.
    /// All kernels returned are actual commits, they are validated before returned as the database can
    /// contain "bad" data for fixes lines.
    /// If no fixes were found, an error is returned
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No fixes for the given git SHA are found in the database
    /// - The database query fails
    /// - Creating a Kernel object from any of the fix IDs fails
    pub fn get_fixes(&self, git_sha: &str) -> Result<Vec<Kernel>> {
        let mut fixed_kernels: Vec<Kernel> = vec![];

        let sql = "
            WITH fix_ids AS (
                SELECT value AS id
                FROM commits, json_each('[\"' || replace(fixes, ' ', '\",\"') || '\"]')
                WHERE commits.id = ?1 AND fixes IS NOT NULL AND fixes != ''
            )
            SELECT id, release
            FROM commits
            WHERE id IN (SELECT id FROM fix_ids)";

        if let Ok(mut stmt) = self.conn.prepare(sql)
            && let Ok(rows) = stmt.query([git_sha]) {
                let mapped_rows =
                    rows.mapped(|row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)));

                for result in mapped_rows.flatten() {
                    if let Ok(k) = Kernel::from_id(&result.0) {
                        fixed_kernels.push(k);
                    }
                }
            }

        if fixed_kernels.is_empty() {
            debug!("No fixes for {git_sha} were found");
            if let Ok(k) = Kernel::from_id(git_sha) {
                debug!("kernel = {:?}", k);
            } else {
                debug!("{git_sha} is not a valid kernel yet, so maybe this is not in the mainline yet?");
                // This commit could just be in Linus's tree, but NOT in a release kernel yet, so
                // let's dig and see if this is in a stable release (this happens at times)
                let result = self.found_in(git_sha, &[]);
                let found = result.unwrap();
                if let Some(k) = found.kernels.into_iter().next() {
                    // We only care about one of these kernels, so just grab the first and go with
                    // that, calling into ourself to get the data
                    debug!("k = {:?}", k);
                    return self.get_fixes(&k.git_id());
                } else {
                    debug!("no kernels were found for this git id.");
                    return Err(anyhow!("No fixes for {git_sha} were found"));
                }
            }
            return Err(anyhow!("No fixes for {git_sha} were found"))
        }

        // Sort the list to be deterministic
        fixed_kernels.sort();
        Ok(fixed_kernels)
    }

    /// Returns a sha for the revert if present
    /// If no revert is found, an error is returned
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No revert for the given git SHA is found in the database
    /// - The database query fails
    /// - Creating a Kernel object from the revert ID fails
    pub fn get_revert(&self, git_sha: &str) -> Result<Kernel> {
        debug!("\tget_revert: '{git_sha}'");

        // Use our query_string function to get a single result
        let revert = query_string(
            &self.conn,
            "SELECT reverts from commits WHERE id=?1",
            &[&git_sha as &dyn ToSql],
        );

        if revert.is_empty() {
            return Err(anyhow!("No revert for {git_sha} was found"));
        }
        let k = match Kernel::from_id(&revert) {
            Ok(k) => k,
            Err(err) => return Err(anyhow!("{err:?}")),
        };
        Ok(k)
    }

    /// Returns raw backport entries from the database without any policy filtering.
    /// This is pure SQL logic - policy decisions are made in `found_in()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails
    fn found_in_raw(&self, git_sha: &str) -> Result<Vec<BackportEntry>> {
        let mut entries = Vec::new();

        // Find all backported commits, including those that were reverted
        // The LEFT JOIN with rev gives us the revert info if present
        let sql = "
            SELECT c.id, c.release, c.reverts, rev.id, rev.release
            FROM commits c
            LEFT JOIN commits rev ON rev.reverts = c.id
            WHERE c.mainline_id = ?1
        ";

        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow!("SQL prepare error: {e:?} for query: {sql}"));
            }
        };

        if let Ok(commit_rows) = stmt.query_map([git_sha], |row| {
            Ok(BackportEntry {
                id: row.get::<_, String>(0)?,
                release: row.get::<_, String>(1)?,
                reverts: row.get::<_, Option<String>>(2)?,
                revert_id: row.get::<_, Option<String>>(3)?,
                revert_release: row.get::<_, Option<String>>(4)?,
            })
        }) {
            for entry in commit_rows.flatten() {
                entries.push(entry);
            }
        }

        // Also check for the mainline commit itself
        let sql_mainline = "SELECT id, release FROM commits WHERE id = ?1";
        if let Ok(mut stmt) = self.conn.prepare(sql_mainline)
            && let Ok(mainline_rows) = stmt.query_map([git_sha], |row| {
                Ok(BackportEntry {
                    id: row.get::<_, String>(0)?,
                    release: row.get::<_, String>(1)?,
                    reverts: None,
                    revert_id: None,
                    revert_release: None,
                })
            }) {
                for entry in mainline_rows.flatten() {
                    entries.push(entry);
                }
            }

        Ok(entries)
    }

    /// Check if a commit reverts a stable-only commit (mainline = 0)
    fn reverts_stable_commit(&self, revert_target: &str) -> bool {
        let sql = "SELECT mainline FROM commits WHERE id = ?";
        let mainline_values = query_u32(&self.conn, sql, &[&revert_target as &dyn ToSql]);
        mainline_values.contains(&0)
    }

    /// Determines the list of kernels where a specific git sha has been backported to, both
    /// mainline and stable kernel releases, if any.
    ///
    /// Returns a `FoundInResult` containing:
    /// - `kernels`: Non-reverted backports
    /// - `reverted_pairs`: Pairs of (reverted_backport, revert_commit) for backports that were
    ///   later reverted. The revert commit can be treated as a "fix" for that branch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git SHA was not backported anywhere (no kernel matches found)
    /// - The database query fails
    /// - Creating a Kernel object from any of the backport IDs fails
    pub fn found_in(&self, git_sha: &str, fixed_set: &[Kernel]) -> Result<FoundInResult> {
        let mut result = FoundInResult::default();

        // Get raw entries from database
        let entries = self.found_in_raw(git_sha)?;

        // Apply policy decisions to each entry
        for entry in entries {
            // Policy: Skip if already in fixed set
            if fixed_set.iter().any(|k| k.git_id() == entry.id) {
                debug!("\t\tfound_in: skipping {} (already in fixed set)", entry.id);
                continue;
            }

            // Policy: Skip commits that revert stable-only commits
            if let Some(ref revert_target) = entry.reverts
                && self.reverts_stable_commit(revert_target)
            {
                debug!("\t\tfound_in: skipping {} as it reverts a stable commit", entry.id);
                continue;
            }

            // Policy: Track reverted backports as vulnerable/fix pairs
            if let (Some(rev_id), Some(rev_release)) = (entry.revert_id, entry.revert_release) {
                let vuln_kernel = Kernel::from_id_no_validate(&entry.id, &entry.release);
                let fix_kernel = Kernel::from_id_no_validate(&rev_id, &rev_release);
                debug!(
                    "\t\tfound_in: backport {} ({}) was reverted by {} ({})",
                    entry.id, entry.release, rev_id, rev_release
                );
                result.reverted_pairs.push((vuln_kernel, fix_kernel));
            } else {
                // Non-reverted backport - add to kernels list
                if let Ok(k) = Kernel::from_id(&entry.id) {
                    result.kernels.push(k);
                }
            }
        }

        if result.kernels.is_empty() && result.reverted_pairs.is_empty() {
            return Err(anyhow!("git id {git_sha} was not backported anywhere"));
        }

        // Sort for deterministic results
        result.kernels.sort();
        debug!("\t\tfound_in: kernels={:?}, reverted_pairs={:?}", result.kernels, result.reverted_pairs);

        Ok(result)
    }

    /// Returns the mainline commit id for a given sha.
    ///
    /// For stable backport commits, returns the mainline_id column.
    /// If not found, returns the sha as-is.
    pub fn get_mainline_id(&self, sha: &str) -> String {
        let mainline_id = query_string(
            &self.conn,
            "SELECT COALESCE(NULLIF(mainline_id, ''), id) FROM commits WHERE id LIKE ?1 || '%'",
            &[&sha as &dyn ToSql],
        );
        if mainline_id.is_empty() {
            sha.to_string()
        } else {
            mainline_id
        }
    }

    // Helper function to get the path to the database
    // Logic taken from dyad source
    fn lookup_verhaal_database_file() -> String {
        let database_file: String;

        // Find the path to the verhaal.db database file using vulns dir
        let vulns_dir = match common::find_vulns_dir() {
            Ok(dir) => dir,
            Err(e) => panic!("Could not find vulns directory: {e}"),
        };

        let verhaal_db_path = vulns_dir.join("tools").join("verhaal").join("verhaal.db");
        match fs::exists(&verhaal_db_path) {
            Ok(true) => database_file = verhaal_db_path.to_string_lossy().into_owned(),
            Ok(false) => panic!(
                "The verhaal database 'verhaal.db' is not found at expected path: {}",
                verhaal_db_path.display()
            ),
            Err(e) => {
                panic!("Error {e}: Something went wrong trying to lookup the path for 'verhaal.db'")
            }
        }
        database_file
    }

    fn verhaal_database_file() -> &'static String {
        VERHAAL_DB.get_or_init(Self::lookup_verhaal_database_file)
    }

}

#[cfg(test)]
mod tests {
    use crate::Verhaal;

    fn get_version(git_id: String) -> String {
        let verhaal = match Verhaal::new() {
            Ok(verhaal) => verhaal,
            Err(error) => panic!("Can not open the database file {error:?}"),
        };

        let version = verhaal.get_version(&git_id);
        match version {
            Ok(version) => version,
            Err(error) => panic!("{error:?}"),
        }
    }

    #[test]
    fn get_version_test() {
        assert_eq!(
            get_version("28cd47f75185c4818b0fb1b46f2f02faaba96376".to_string()),
            "6.11"
        );
        assert_eq!(
            get_version("22207fd5c80177b860279653d017474b2812af5e".to_string()),
            "6.9"
        );
        assert_eq!(
            get_version("22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string()),
            "6.8.3"
        );
        assert_eq!(
            get_version("af054a5fb24a144f99895afce9519d709891894c".to_string()),
            "6.7.12"
        );
        assert_eq!(
            get_version("2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string()),
            "6.1.132"
        );
        assert_eq!(
            get_version("e87e08c94c9541b4e18c4c13f2f605935f512605".to_string()),
            "6.6.24"
        );
    }

    #[test]
    #[should_panic(expected = "Version 00000000 not found")]
    fn get_invalid_version_test() {
        assert_eq!(get_version("00000000".to_string()), "0.0");
    }

    /// Test found_in returns revert information for CVE-2024-27005
    ///
    /// The introducing commit af42269c3523 was backported to:
    /// - 6.1.55 as ee42bfc791aa (later reverted by 19ec82b3cad1 in 6.1.81)
    /// - 5.15.133 as 9be2957f014d (later reverted by fe549d8e9763 in 5.15.151)
    /// - 6.5.5 as 2f3a124696d4 (NOT reverted - still vulnerable)
    /// - 6.6 as af42269c3523 (NOT reverted - mainline)
    #[test]
    fn found_in_returns_reverted_pairs_test() {
        let verhaal = match Verhaal::new() {
            Ok(verhaal) => verhaal,
            Err(error) => panic!("Can not open the database file {error:?}"),
        };

        // af42269c3523 is the mainline introducing commit for CVE-2024-27005
        let introducing_sha = "af42269c3523492d71ebbe11fefae2653e9cdc78";
        let result = verhaal.found_in(introducing_sha, &[]);

        assert!(result.is_ok(), "Should find backports");
        let found = result.unwrap();

        // Should have some non-reverted backports (6.5.5, 6.6, etc.)
        assert!(!found.kernels.is_empty(), "Should find non-reverted backports");

        // Should find at least 2 revert-based fixes (6.1 and 5.15)
        assert!(
            found.reverted_pairs.len() >= 2,
            "Should find at least 2 revert-based fix pairs, found {}",
            found.reverted_pairs.len()
        );

        // Check for the 6.1 revert-based fix
        let has_6_1_fix = found.reverted_pairs.iter().any(|(vuln, fix)| {
            vuln.git_id() == "ee42bfc791aa3cd78e29046f26a09d189beb3efb"
                && fix.git_id() == "19ec82b3cad1abef2a929262b8c1528f4e0c192d"
                && vuln.version() == "6.1.55"
                && fix.version() == "6.1.81"
        });
        assert!(
            has_6_1_fix,
            "Should find 6.1 revert-based fix: 6.1.55 (ee42bfc791aa) -> 6.1.81 (19ec82b3cad1)"
        );

        // Check for the 5.15 revert-based fix
        let has_5_15_fix = found.reverted_pairs.iter().any(|(vuln, fix)| {
            vuln.git_id() == "9be2957f014d91088db1eb5dd09d9a03d7184dce"
                && fix.git_id() == "fe549d8e976300d0dd75bd904eb216bed8b145e0"
                && vuln.version() == "5.15.133"
                && fix.version() == "5.15.151"
        });
        assert!(
            has_5_15_fix,
            "Should find 5.15 revert-based fix: 5.15.133 (9be2957f014d) -> 5.15.151 (fe549d8e9763)"
        );

        // Check that 6.5.5 is in kernels (non-reverted)
        let has_6_5_5 = found.kernels.iter().any(|k| {
            k.git_id() == "2f3a124696d43de3c837f87a9f767c56ee86cf2a" && k.version() == "6.5.5"
        });
        assert!(has_6_5_5, "Should find 6.5.5 as non-reverted backport");
    }
}
