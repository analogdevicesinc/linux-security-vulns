#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Build post.db: combined CVE files + SHA database + filtered kernel commits.
#
# Tables:
#   files(cve, file)              - CVE to affected source files
#   cves(cve, sha, role)          - CVE to fix/vuln SHAs; role: 1=fix, 0=vuln
#   commits(id, release,          - Filtered subset of verhaal.db commits:
#           mainline_id)            CVE-referenced SHAs and stable backports
#                                   of fix SHAs (for cherry-pick resolution).
#
# Usage:
#   python3 build-post-db.py [vulns_dir] [output_db] [verhaal_db]

import json
import sqlite3
import sys
from pathlib import Path

vulns_dir    = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
db_path      = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("post.db")
verhaal_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None
published = vulns_dir / "cve" / "published"

if not published.is_dir():
    print(f"::error :: {published} does not exist", file=sys.stderr)
    sys.exit(1)

db_path.unlink(missing_ok=True)
con = sqlite3.connect(db_path)
con.execute(
    "CREATE TABLE files ("
    "  cve  TEXT NOT NULL,"
    "  file TEXT NOT NULL,"
    "  UNIQUE(cve, file)"
    ")"
)
con.execute("CREATE INDEX idx_files_file ON files(file)")
con.execute("CREATE INDEX idx_files_cve  ON files(cve)")
con.execute(
    "CREATE TABLE cves ("
    "  cve  TEXT NOT NULL,"
    "  sha  TEXT NOT NULL,"
    "  role INTEGER NOT NULL DEFAULT 1"  # 1=fix, 0=vuln
    ")"
)
con.execute("CREATE INDEX idx_cve_cve ON cves(cve)")
con.execute("CREATE INDEX idx_cve_sha ON cves(sha)")

for path in sorted(published.rglob("CVE-*.json")):
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"::warning :: skipping {path.name}: {e}", file=sys.stderr)
        continue
    cve = path.stem
    program_files = {
        f
        for a in data.get("containers", {}).get("cna", {}).get("affected", [])
        for f in a.get("programFiles", [])
    }
    if program_files:
        with con:
            con.executemany(
                "INSERT OR IGNORE INTO files VALUES(?, ?)",
                ((cve, f) for f in program_files),
            )

for path in sorted(published.rglob("CVE-*.dyad")):
    cve = path.stem
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        vuln_ver, vuln_sha, fix_ver, fix_sha = (
            parts[0], parts[1], parts[2], parts[3]
        )
        if vuln_sha and vuln_sha != "0":
            rows.append((cve, vuln_sha, 0))
        if fix_sha and fix_sha != "0":
            rows.append((cve, fix_sha, 1))
    if rows:
        with con:
            con.executemany("INSERT INTO cves VALUES(?, ?, ?)", rows)

# Merge filtered commits from verhaal.db so grondig needs only post.db.
# Includes:
#   - every commit directly referenced in the cves table (for version lookups)
#   - every stable-branch commit whose mainline_id is a fix SHA (so cherry-pick
#     resolution works when users supply stable backport SHAs)
def build_commits_table():
    if verhaal_path is None or not verhaal_path.exists():
            print(f"::error :: verhaal.db not found at {verhaal_path}",
                  file=sys.stderr)
            sys.exit(1)

    con.execute(
        "CREATE TABLE commits ("
        "  id          TEXT PRIMARY KEY,"
        "  release     TEXT NOT NULL,"
        "  mainline_id TEXT"
        ")"
    )
    con.execute("CREATE INDEX idx_commits_mainline_id ON commits(mainline_id)")
    con.commit()

    # Use temp tables in verhaal to avoid the SQLite per-query variable limit.
    vcon = sqlite3.connect(str(verhaal_path))
    vcon.execute("CREATE TEMP TABLE _post_sha (sha TEXT PRIMARY KEY)")
    vcon.execute("CREATE TEMP TABLE _fix_sha  (sha TEXT PRIMARY KEY)")
    vcon.executemany(
        "INSERT OR IGNORE INTO _post_sha VALUES(?)",
        con.execute("SELECT DISTINCT sha FROM cves"),
    )
    vcon.executemany(
        "INSERT OR IGNORE INTO _fix_sha VALUES(?)",
        con.execute("SELECT sha FROM cves WHERE role=1"),
    )
    vcon.commit()

    rows = vcon.execute("""
        SELECT c.id, c.release, NULLIF(c.mainline_id, '')
        FROM commits c
        WHERE c.id IN (SELECT sha FROM _post_sha)
           OR (    c.mainline_id IS NOT NULL
               AND c.mainline_id != ''
               AND c.mainline_id IN (SELECT sha FROM _fix_sha))
    """).fetchall()
    vcon.close()

    with con:
        con.executemany("INSERT OR IGNORE INTO commits VALUES(?, ?, ?)", rows)
    print(f"commits: {len(rows)} rows imported from verhaal.db")

build_commits_table()

print(f"post.db: done")
