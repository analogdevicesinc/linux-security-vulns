#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense
#
# Mark CSA vulnerabilities 'new' as 'not_affected' or 'needs_review' if
# they are or not confirmed by 'grondig' output.
#
# Usage:
#   echo '<grondig-json>' | python3 linux2sca.py \
#       --url     https://csa.example.com \
#       --token   <bearer-token> \
#       --project <project-id> \
#       [--dry-run]

import sys
import argparse
import json
import urllib.request
import urllib.error


def csa_get(url, token):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def csa_put(url, token, body, dry_run):
    if dry_run:
        print(f"  [dry-run] PUT {url}", flush=True)
        return 200
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="PUT", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def set_vuln_status(base_url, project, cve, token, new_status, comment, dry_run):
    """PUT /api/projects/{project}/vulnerabilities/{cve}/status."""
    url = f"{base_url}/api/projects/{project}/vulnerabilities/{cve}/status"
    status = csa_put(url, token, {
        "status": new_status,
        "comment": comment,
    }, dry_run)
    return str(status).startswith("2")


def paginate(base_url, token):
    """Paginate CSA API responses."""
    limit = 100
    offset = 0
    while True:
        url = f"{base_url}?offset={offset}&limit={limit}"
        page = csa_get(url, token)
        items = page.get("items", [])
        yield from items
        offset += limit
        if offset >= page.get("total", 0):
            break


def merge_cves_from_defconfigs(data):
    """Return the merged set of CVE IDs of defconfigs.
    If in your CSA you have versions for each defconfig,
    don't use this method."""
    cves = set()
    for entry in data.values():
        for cve in entry.get("cves", []):
            cves.add(cve)
    return cves


def main():
    parser = argparse.ArgumentParser(
        description="Mark CSA vulnerabilities as not_affected based on grondig output"
    )
    parser.add_argument("--url",     required=True, help="CSA base URL (e.g. https://csa.example.com)")
    parser.add_argument("--token",   required=True, help="Bearer token")
    parser.add_argument("--project", required=True, help="CSA project ID")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print PUTs without executing them")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    raw = sys.stdin.read().strip()
    if not raw:
        sys.exit(1)
    grondig_cves = merge_cves_from_defconfigs(json.loads(raw))
    print(f"Grondig CVEs across all defconfigs: {len(grondig_cves)}", flush=True)

    vulns_url = f"{base_url}/api/projects/{args.project}/vulnerabilities"
    print(f"Fetching vulnerabilities from {vulns_url} ...", flush=True)

    not_affected = needs_review = skipped = errors = 0

    for item in paginate(vulns_url, args.token):
        cve    = item.get("cve", "")
        status = item.get("status", "")

        if cve in grondig_cves:
            if status == "needs_review":
                skipped += 1
                continue
            ok = set_vuln_status(base_url, args.project, cve, args.token,
                                 "needs_review",
                                 "grondig: affected source files are compiled in the image",
                                 args.dry_run)
            if ok:
                needs_review += 1
                print(f"  needs_review {cve}", flush=True)
            else:
                errors += 1
                print(f"  ERROR        {cve} (HTTP failed)", file=sys.stderr, flush=True)
        else:
            if status == "not_affected":
                skipped += 1
                continue
            ok = set_vuln_status(base_url, args.project, cve, args.token,
                                 "not_affected",
                                 "grondig: affected source files are not compiled in the image",
                                 args.dry_run)
            if ok:
                not_affected += 1
                print(f"  not_affected {cve}", flush=True)
            else:
                errors += 1
                print(f"  ERROR        {cve} (HTTP failed)", file=sys.stderr, flush=True)

    print(f"\nDone: {not_affected} not_affected, {needs_review} needs_review, "
          f"{skipped} skipped, {errors} errors")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
