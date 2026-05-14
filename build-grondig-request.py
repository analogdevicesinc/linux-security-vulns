#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Build a grondig JSON request from SBOM / compile_commands files.
#
# Usage:
#   echo -e "file1.json\nfile2.json" | \
#       python3 build-grondig-request.py --tag v6.12.5 [--cherry-picks sha1,sha2]
#
# Reads file paths (one per line) from stdin.
# Writes the grondig JSON request to stdout.

import argparse
import json
import sys


def files_from_cdx(data):
    return [
        c["name"]
        for c in data.get("metadata", {}).get("component", {}).get("components", [])
        if c.get("name")
    ]


def files_from_spdx(data):
    return [
        e["name"]
        for e in data.get("@graph", [])
        if e.get("type") == "software_File"
        and e.get("software_primaryPurpose") == "source"
        and e.get("name", "").endswith((".c", ".S"))
    ]


def _is_kernelsom_source(data):
    # https://github.com/TNG/KernelSbom
    return any(
        e.get("type") == "SoftwareAgent" and e.get("name") == "KernelSbom"
        for e in data.get("@graph", [])
    )


def files_from_kernelsom_source(data):
    return files_from_spdx(data)


def files_from_compile_commands(data):
    src_root = next(
        (e["file"][: -len("init/main.c")] for e in data if e["file"].endswith("/init/main.c")),
        None,
    )
    if not src_root:
        print("error: cannot find init/main.c in compile_commands.json", file=sys.stderr)
        sys.exit(1)
    return [e["file"][len(src_root) :] for e in data if e["file"].startswith(src_root)]


def main():
    parser = argparse.ArgumentParser(
        description="Build a grondig JSON request from SBOM/compile_commands files"
    )
    parser.add_argument("--tag", required=True, help="Kernel stable-tag (e.g. v6.12.5)")
    parser.add_argument(
        "--cherry-picks", default="", help="Comma- or space-separated cherry-picked SHAs"
    )
    args = parser.parse_args()

    cherry_picks = [s for s in args.cherry_picks.replace(",", " ").split() if s]

    request = {}
    for f in (line.strip() for line in sys.stdin if line.strip()):
        try:
            data = json.load(open(f))
        except Exception as e:
            print(f"warning: {f}: {e}", file=sys.stderr)
            continue

        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            files = files_from_cdx(data)
        elif isinstance(data, dict) and "@graph" in data and _is_kernelsom_source(data):
            files = files_from_kernelsom_source(data)
        elif isinstance(data, dict) and "@graph" in data:
            files = files_from_spdx(data)
        elif isinstance(data, list):
            files = files_from_compile_commands(data)
        else:
            print(f"warning: {f}: unrecognised format", file=sys.stderr)
            continue

        request[f] = {
            "stable-tag":     args.tag,
            "cherry-picked":  cherry_picks,
            "compiled-files": files,
        }

    print(json.dumps(request))


if __name__ == "__main__":
    main()
