#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Build post.db: combined CVE files + SHA database.
#
# Tables:
#   files(cve, file)    - CVE to affected source files
#   sha(cve, sha, role) - CVE to fix/vuln SHAs; role: 1=fix, 0=vuln
#
# Usage:
#   python3 build-post-db.py [vulns_dir] [output_db]

import json
import sqlite3
import sys
from pathlib import Path

vulns_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
db_path   = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("post.db")
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
    "CREATE TABLE sha ("
    "  cve  TEXT NOT NULL,"
    "  sha  TEXT NOT NULL,"
    "  role INTEGER NOT NULL DEFAULT 1"  # 1=fix, 0=vuln
    ")"
)
con.execute("CREATE INDEX idx_sha_cve ON sha(cve)")
con.execute("CREATE INDEX idx_sha_sha ON sha(sha)")

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
            con.executemany("INSERT INTO sha VALUES(?, ?, ?)", rows)

print(f"post.db: done")
