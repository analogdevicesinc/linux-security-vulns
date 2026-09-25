#!/usr/bin/env python3
"""
Git merge driver for JSON files.
  driver = python3 ./json-merge.py %O %A %B %L %P
"""

import json, os, sys


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError, OSError):
        return {}


_, _O, ours_path, _B, _L, file_path = sys.argv
ours, theirs = load(ours_path), load(_B)
name = os.path.basename(file_path)

if name == "refs.json":
    result = sorted(set((ours if isinstance(ours, list) else [])
                      + (theirs if isinstance(theirs, list) else [])))
elif name == "tags.json":
    result = {**theirs, **ours}
else:
    result = ours

with open(ours_path, "w") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
