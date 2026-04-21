#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Reconstruct the vulns/cve/published/*.dyad file tree from dyads.db.
# strak locates the vulns directory by traversing up from its own binary
# or from cwd; the .dyad files must sit under vulns/cve/published/<year>/.

import sqlite3, sys
from pathlib import Path

db_path      = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dyads.db")
published    = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("vulns/cve/published")

con = sqlite3.connect(db_path)
count = 0
for year, cve, content in con.execute("SELECT year, cve, content FROM dyads"):
    dest = published / year / f"{cve}.dyad"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    count += 1

print(f"Restored {count} .dyad files into {published}")
