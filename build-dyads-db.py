#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Pack all .dyad files from vulns/cve/published into a SQLite database.
# This lets the check step reconstruct only the .dyad tree that strak
# needs at runtime, without cloning the full vulns repository.

import sqlite3, sys
from pathlib import Path

vulns_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("vulns")
published = vulns_dir / "cve" / "published"
db_path   = Path("dyads.db")

db_path.unlink(missing_ok=True)
con = sqlite3.connect(db_path)
con.execute("CREATE TABLE dyads (year TEXT NOT NULL, cve TEXT NOT NULL, content TEXT NOT NULL)")

count = 0
with con:
    for path in sorted(published.rglob("*.dyad")):
        year = path.parent.name
        cve  = path.stem          # e.g. CVE-2020-36790
        con.execute("INSERT INTO dyads VALUES(?, ?, ?)",
                    (year, cve, path.read_text()))
        count += 1

print(f"dyads.db: packed {count} .dyad files")
