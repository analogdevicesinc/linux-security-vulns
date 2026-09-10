#!/usr/bin/env python3

import json
import sys
from urllib.parse import quote

result_file, output_file, repository, ref, sha = sys.argv[1:]

with open(result_file) as f:
    grondig = json.load(f)

cves = sorted({
    cve
    for files in grondig.values()
    for file_cves in files.values()
    for cve in file_cves
})
rules = [
    {
        "id": cve,
        "shortDescription": {"text": cve},
        "helpUri": f"https://www.cve.org/CVERecord?id={cve}",
    }
    for cve in cves
]
rule_index = {cve: i for i, cve in enumerate(cves)}
results = []
for artifact, files in sorted(grondig.items()):
    by_cve = {}
    for file, file_cves in files.items():
        for cve in file_cves:
            by_cve.setdefault(cve, []).append(file)
    for cve, affected_files in sorted(by_cve.items()):
        results.append({
            "ruleId": cve,
            "ruleIndex": rule_index[cve],
            "level": "warning",
            "message": {"text": f"{cve} affects {artifact}."},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": quote(file, safe="/")},
                    },
                    "logicalLocations": [{
                        "name": artifact,
                        "fullyQualifiedName": artifact,
                        "kind": "configuration",
                    }],
                }
                for file in sorted(affected_files)
            ],
            "partialFingerprints": {
                "grondigCveArtifact/v1": f"{artifact}:{cve}",
            },
        })

sarif = {
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "grondig",
                "informationUri": "https://github.com/analogdevicesinc/linux-security-vulns",
                "rules": rules,
            },
        },
        "invocations": [{"executionSuccessful": True}],
        "results": results,
        "properties": {
            "repository": repository,
            "ref": ref,
            "sha": sha,
        },
    }],
}

with open(output_file, "w") as f:
    json.dump(sarif, f, indent=2)
    f.write("\n")
