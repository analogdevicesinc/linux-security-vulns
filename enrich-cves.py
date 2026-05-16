import json, zipfile, sys

with open('refs.json') as f:
    refs = json.load(f)

cves = set()
for ref in refs:
    with open(ref) as f:
        for entry in json.load(f).values():
            cves.update(entry.get('cves', []))
cves = sorted(cves)

scores, summaries = [], []
with zipfile.ZipFile(sys.argv[1]) as z:
    names = set(z.namelist())
    for cve in cves:
        fname = f'{cve}.json'
        if fname not in names:
            scores.append(None)
            summaries.append(None)
            continue

        d = json.loads(z.read(fname))
        sev = next((s for s in d.get('severity', []) if s['type'] == 'CVSS_V3'), None)
        scores.append(sev['score'] if sev else None)
        summaries.append(d.get('summary'))

with open('scores.json', 'w') as f:
    json.dump({'cve': cves, 'cvss_score': scores, 'summary': summaries}, f)
