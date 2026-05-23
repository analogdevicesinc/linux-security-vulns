# DEMO only, you should use a DB.
import json, zipfile, sys, os, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
WORKERS = 20 if NVD_API_KEY else 3

def nvd_score(cve_id):
    req = urllib.request.Request(NVD_API.format(cve_id))
    if NVD_API_KEY:
        req.add_header('apiKey', NVD_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        metrics = data['vulnerabilities'][0]['cve'].get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30'):
            m = metrics.get(key, [])
            if m:
                return m[0]['cvssData']['vectorString']
    except Exception:
        pass
    return None

with open('refs.json') as f:
    refs = json.load(f)

cves = set()
for ref in refs:
    print(f"got {ref}")
    with open(ref) as f:
        json_ = json.load(f)
        if 'result' not in json_:
            continue
        for entry in json_['result'].values():
            cves.update(entry.get('cves', []))
cves = sorted(cves)

scores = {}
summaries = {}
with zipfile.ZipFile(sys.argv[1]) as z:
    names = set(z.namelist())
    for cve in cves:
        fname = f'{cve}.json'
        if fname in names:
            d = json.loads(z.read(fname))
            sev = next((s for s in d.get('severity', []) if s['type'] == 'CVSS_V3'), None)
            scores[cve] = sev['score'] if sev else None
            summaries[cve] = d.get('summary')
        else:
            scores[cve] = None
            summaries[cve] = None

if os.path.exists(sys.argv[2]):
    with open(sys.argv[2]) as f:
        prev = json.load(f)
    for cve, score in zip(prev['cve'], prev['cvss_score']):
        if score is not None and scores.get(cve) is None:
            scores[cve] = score

need_nvd = [c for c in cves if scores[c] is None]
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futures = {ex.submit(nvd_score, c): c for c in need_nvd}
    for fut in as_completed(futures):
        cve = futures[fut]
        scores[cve] = fut.result()

with open(sys.argv[2], 'w') as f:
    json.dump({'cve': cves, 'cvss_score': [scores[c] for c in cves], 'summary': [summaries[c] for c in cves]}, f)
