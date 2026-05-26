#!/usr/bin/env python3
"""
Git merge driver for JSON files.
  driver = python3 ./json-merge.py %O %A %B %L %P
"""

import json, os, sys


def merge_scores(ours, theirs):
    merged = {}
    for src in (ours, theirs):
        for i, cve in enumerate(src.get("cve", [])):
            prev = merged.get(cve, {})
            s, m = src["cvss_score"][i], src["summary"][i]
            merged[cve] = {
                "cvss_score": s if s is not None else prev.get("cvss_score"),
                "summary":    m if m is not None else prev.get("summary"),
            }
    cves = sorted(merged)
    return {
        "cve":        cves,
        "cvss_score": [merged[c]["cvss_score"] for c in cves],
        "summary":    [merged[c]["summary"]    for c in cves],
    }


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError, OSError):
        return {}


_, _O, ours_path, _B, _L, file_path = sys.argv
ours, theirs = load(ours_path), load(_B)
name = os.path.basename(file_path)

if name == "scores.json":
    result = merge_scores(ours, theirs)
elif name == "refs.json":
    result = sorted(set((ours if isinstance(ours, list) else [])
                      + (theirs if isinstance(theirs, list) else [])))
elif name == "tags.json":
    result = {**theirs, **ours}
else:
    result = ours

with open(ours_path, "w") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
