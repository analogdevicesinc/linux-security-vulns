// SPDX-License-Identifier: GPL-2.0-only
//
// grondig — Crossplane Composition Function (gRPC) for kernel CVE analysis.
//
// Implements FunctionRunnerService (proto/fn/v1/run_function.proto).
// Input:  observed XR spec.stableTag, spec.cherryPicked, spec.compiledFiles
// Output: result message + "GrondigReady" condition + context "grondig/cves"
//
// "grondig" means "thorough" in Dutch.
//
// Copyright (c) 2026 - Jorge Marques <jorge.marques@analog.com>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Value};
use rusqlite::Connection;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

pub mod fnv1 {
    include!(concat!(env!("OUT_DIR"), "/apiextensions.r#fn.proto.v1.rs"));
}

use fnv1::function_runner_service_server::{
    FunctionRunnerService, FunctionRunnerServiceServer,
};
use fnv1::{
    Condition, ResponseMeta, Result as FnResult, RunFunctionRequest,
    RunFunctionResponse, Severity, Status as CondStatus, Target,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelVersion {
    components: Vec<u32>,
    rc_num: Option<u32>,
    is_queue: bool,
    is_rc_by_name: bool,
}

impl KernelVersion {
    fn is_rc(&self) -> bool {
        self.rc_num.is_some() || self.is_rc_by_name
    }

    fn is_mainline(&self) -> bool {
        if self.components.is_empty() || self.components[0] == 0 {
            return false;
        }
        if self.is_rc() {
            return true;
        }
        if self.is_queue {
            return false;
        }
        if self.components.len() >= 3
            && self.components[0] == 2
            && (self.components[1] == 6 || self.components[1] == 4)
        {
            return self.components.len() == 3;
        }
        self.components.len() == 2
    }

    fn major_version(&self) -> String {
        if self.components.is_empty() {
            return String::new();
        }
        if self.components.len() >= 3 && self.components[0] == 2 && self.components[1] == 6 {
            return format!("2.6.{}", self.components[2]);
        }
        if self.components.len() >= 2 {
            return format!("{}.{}", self.components[0], self.components[1]);
        }
        String::new()
    }

    fn major_matches(&self, other: &Self) -> bool {
        !self.major_version().is_empty()
            && self.major_version() == other.major_version()
    }
}

impl FromStr for KernelVersion {
    type Err = ();

    fn from_str(version: &str) -> std::result::Result<Self, ()> {
        let is_queue = version.contains("-queue");
        let is_rc_by_name = version.contains("-rc");
        let (base_version, rc_num) = version.find("-rc").map_or((version, None), |rc_idx| {
            let base = &version[0..rc_idx];
            let rc_number = if rc_idx + 3 < version.len() {
                version[rc_idx + 3..].parse::<u32>().ok()
            } else {
                Some(0)
            };
            (base, rc_number)
        });
        let components: Vec<u32> = base_version
            .split('.')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect();
        Ok(Self { components, rc_num, is_queue, is_rc_by_name })
    }
}

impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.major_matches(other) {
            if self.is_mainline() && !other.is_mainline() {
                return Ordering::Less;
            }
            if !self.is_mainline() && other.is_mainline() {
                return Ordering::Greater;
            }
        }
        let max_len = std::cmp::max(self.components.len(), other.components.len());
        for i in 0..max_len {
            let v1 = self.components.get(i).copied().unwrap_or(0);
            let v2 = other.components.get(i).copied().unwrap_or(0);
            match v1.cmp(&v2) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }
        match (self.is_rc(), other.is_rc()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (true, true) => self.rc_num.unwrap_or(0).cmp(&other.rc_num.unwrap_or(0)),
            (false, false) => Ordering::Equal,
        }
    }
}

fn version_is_mainline(version: &str) -> bool {
    KernelVersion::from_str(version).map(|v| v.is_mainline()).unwrap_or(false)
}

fn kernel_version_major(version: &str) -> String {
    KernelVersion::from_str(version).map(|v| v.major_version()).unwrap_or_default()
}

fn compare_kernel_versions(v1: &str, v2: &str) -> Ordering {
    if v1 == v2 {
        return Ordering::Equal;
    }
    match (KernelVersion::from_str(v1), KernelVersion::from_str(v2)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => v1.cmp(v2),
    }
}

// ---------------------------------------------------------------------------

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
            .prepare("SELECT DISTINCT cve FROM cves ORDER BY cve")
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
            .prepare("SELECT sha FROM cves WHERE cve=?1 AND role=?2")
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

    /// Returns the kernel release version for a SHA, or "" if not found.
    fn get_version(&self, sha: &str) -> String {
        self.conn
            .query_row(
                "SELECT release FROM commits WHERE id=?1",
                [sha],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_default()
    }

    /// Returns the mainline commit id for a SHA.
    /// For stable backports returns the mainline_id column; otherwise returns sha as-is.
    fn get_mainline_id(&self, sha: &str) -> String {
        self.conn
            .query_row(
                "SELECT COALESCE(mainline_id, id) FROM commits WHERE id LIKE ?1 || '%'",
                [sha],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_else(|_| sha.to_string())
    }
}

/// Returns true if `candidate` version is reachable from `target`.
fn version_reachable(candidate: &str, target: &str) -> bool {
    if candidate.is_empty() || candidate == "0" {
        return true;
    }
    if version_is_mainline(candidate) {
        compare_kernel_versions(candidate, target) != Ordering::Greater
    } else {
        kernel_version_major(candidate) == kernel_version_major(target)
            && compare_kernel_versions(candidate, target) != Ordering::Greater
    }
}

/// Expands raw cherry-pick SHAs to also include their mainline equivalents.
fn expand_cherry_picks(raw: &[String], post_db: &PostDb) -> HashSet<String> {
    let mut set = HashSet::new();
    for sha in raw {
        let lower = sha.to_lowercase();
        let mainline = post_db.get_mainline_id(&lower);
        set.insert(lower);
        set.insert(mainline);
    }
    set
}

/// Returns true if the CVE is unfixed in `target` accounting for `cherry_picks`.
fn is_cve_unfixed(
    post_db: &PostDb,
    cve: &str,
    target: &str,
    cherry_picks: &HashSet<String>,
) -> bool {
    let vuln_shas = post_db.shas_for(cve, 0);
    let fix_shas = post_db.shas_for(cve, 1);

    let affected = if vuln_shas.is_empty() {
        true
    } else {
        vuln_shas.iter().any(|sha| version_reachable(&post_db.get_version(sha), target))
    };

    if !affected {
        return false;
    }

    let fixed = fix_shas.iter().any(|sha| {
        version_reachable(&post_db.get_version(sha), target)
            || cherry_picks.contains(sha.as_str())
    });

    !fixed
}

/// Compute the list of unfixed CVEs for one SBOM entry.
fn compute_cves(
    post_db: &PostDb,
    stable_tag: &str,
    cherry_picked: &[String],
    compiled_files: &[String],
) -> Vec<String> {
    let target = stable_tag.strip_prefix('v').unwrap_or(stable_tag);
    let cherry_picks = expand_cherry_picks(cherry_picked, post_db);
    let files_set: HashSet<&str> = compiled_files.iter().map(String::as_str).collect();

    post_db
        .all_cves()
        .into_iter()
        .filter(|cve| is_cve_unfixed(post_db, cve, target, &cherry_picks))
        .filter(|cve| {
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

// ---------------------------------------------------------------------------
// gRPC service
// ---------------------------------------------------------------------------

struct GrondigFunction {
    db: Arc<Mutex<PostDb>>,
}

#[tonic::async_trait]
impl FunctionRunnerService for GrondigFunction {
    async fn run_function(
        &self,
        request: Request<RunFunctionRequest>,
    ) -> std::result::Result<Response<RunFunctionResponse>, Status> {
        let req = request.into_inner();
        let tag = req.meta.as_ref().map_or("", |m| &m.tag).to_string();

        // Extract SBOM inputs from observed XR spec.
        let xr_spec = req
            .observed
            .as_ref()
            .and_then(|s| s.composite.as_ref())
            .and_then(|r| r.resource.as_ref())
            .and_then(|st| st.fields.get("spec"))
            .and_then(|v| match &v.kind {
                Some(Kind::StructValue(s)) => Some(s),
                _ => None,
            });

        let (stable_tag, cherry_picked, compiled_files) = match xr_spec {
            None => return Ok(Response::new(fatal(&tag, "MissingSpec",
                "observed composite resource has no spec"))),
            Some(spec) => {
                let stable_tag = str_field(spec, "stableTag").unwrap_or_default();
                if stable_tag.is_empty() {
                    return Ok(Response::new(fatal(&tag, "MissingStableTag",
                        "spec.stableTag is required")));
                }
                (stable_tag, str_list(spec, "cherryPicked"), str_list(spec, "compiledFiles"))
            }
        };

        // Run CVE analysis (blocking SQLite → spawn_blocking).
        let db = Arc::clone(&self.db);
        let tag_clone = stable_tag.clone();
        let cves = tokio::task::spawn_blocking(move || {
            let db = db.lock().expect("PostDb mutex poisoned");
            compute_cves(&db, &tag_clone, &cherry_picked, &compiled_files)
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking panicked: {e}")))?;

        let msg = if cves.is_empty() {
            format!("grondig: no unfixed CVEs for {stable_tag}")
        } else {
            format!("grondig: {} unfixed CVE(s) for {stable_tag}: {}",
                    cves.len(), cves.join(", "))
        };

        // Pass CVE list to downstream functions via pipeline context.
        let context = {
            let mut ctx = req.context.unwrap_or_default();
            ctx.fields.insert("grondig/cves".into(), Value {
                kind: Some(Kind::ListValue(ListValue {
                    values: cves.iter()
                        .map(|c| Value { kind: Some(Kind::StringValue(c.clone())) })
                        .collect(),
                })),
            });
            ctx
        };

        Ok(Response::new(RunFunctionResponse {
            meta: Some(ResponseMeta { tag, ttl: None }),
            desired: req.desired,
            context: Some(context),
            results: vec![FnResult {
                severity: Severity::Normal as i32,
                message: msg,
                reason: Some("CVEsComputed".into()),
                target: Some(Target::Composite as i32),
            }],
            conditions: vec![Condition {
                r#type: "GrondigReady".into(),
                status: CondStatus::ConditionTrue as i32,
                reason: "CVEsComputed".into(),
                message: Some(format!("{} unfixed CVE(s)", cves.len())),
                target: Some(Target::Composite as i32),
            }],
            ..Default::default()
        }))
    }
}

fn str_field(s: &Struct, key: &str) -> Option<String> {
    s.fields.get(key).and_then(|v| match &v.kind {
        Some(Kind::StringValue(sv)) => Some(sv.clone()),
        _ => None,
    })
}

fn str_list(s: &Struct, key: &str) -> Vec<String> {
    s.fields.get(key)
        .and_then(|v| match &v.kind {
            Some(Kind::ListValue(lv)) => Some(lv),
            _ => None,
        })
        .map(|lv| lv.values.iter()
            .filter_map(|v| match &v.kind {
                Some(Kind::StringValue(sv)) => Some(sv.clone()),
                _ => None,
            })
            .collect())
        .unwrap_or_default()
}

fn fatal(tag: &str, reason: &str, message: &str) -> RunFunctionResponse {
    RunFunctionResponse {
        meta: Some(ResponseMeta { tag: tag.into(), ttl: None }),
        results: vec![FnResult {
            severity: Severity::Fatal as i32,
            message: message.into(),
            reason: Some(reason.into()),
            target: Some(Target::Composite as i32),
        }],
        conditions: vec![Condition {
            r#type: "GrondigReady".into(),
            status: CondStatus::ConditionFalse as i32,
            reason: reason.into(),
            message: Some(message.into()),
            target: Some(Target::Composite as i32),
        }],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// CLI + main
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[clap(about = "Crossplane Function gRPC server for grondig")]
struct Args {
    /// Address to listen on.
    #[clap(long, default_value = "0.0.0.0:9443")]
    address: String,

    /// Directory containing mTLS certs (tls.key, tls.crt, ca.crt).
    #[clap(long, env = "TLS_SERVER_CERTS_DIR")]
    tls_certs_dir: Option<PathBuf>,

    /// Run without mTLS (development only).
    #[clap(long)]
    insecure: bool,

    /// Path to post.db.
    #[clap(long, default_value = "/post.db")]
    post_db: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let db = Arc::new(Mutex::new(PostDb::open(&args.post_db)?));
    let addr: std::net::SocketAddr = args.address.parse()
        .with_context(|| format!("invalid listen address: {}", args.address))?;
    let svc = FunctionRunnerServiceServer::new(GrondigFunction { db });

    if args.insecure {
        eprintln!("grondig: listening insecurely on {addr}");
        let listener = TcpListener::bind(addr).await?;
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await?;
    } else {
        let dir = args.tls_certs_dir
            .ok_or_else(|| anyhow!("TLS_SERVER_CERTS_DIR required unless --insecure"))?;
        let cert = std::fs::read(dir.join("tls.crt"))
            .with_context(|| format!("read {}/tls.crt", dir.display()))?;
        let key = std::fs::read(dir.join("tls.key"))
            .with_context(|| format!("read {}/tls.key", dir.display()))?;
        let ca = std::fs::read(dir.join("ca.crt"))
            .with_context(|| format!("read {}/ca.crt", dir.display()))?;

        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(&cert, &key))
            .client_ca_root(Certificate::from_pem(&ca));

        eprintln!("grondig: listening with mTLS on {addr}");
        Server::builder().tls_config(tls)?.add_service(svc).serve(addr).await?;
    }

    Ok(())
}
