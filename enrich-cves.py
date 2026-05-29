# DEMO only, you should use a DB.
import json, sys, os, urllib.request, urllib.error, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
RATE_LIMIT = 20 if NVD_API_KEY else 1

print(f"rate_limit: {RATE_LIMIT}/s")

_sema = threading.Semaphore(RATE_LIMIT)
_sema_count = RATE_LIMIT
_sema_lock = threading.Lock()

def _refill():
    global _sema_count
    while True:
        time.sleep(1)
        with _sema_lock:
            to_add = RATE_LIMIT - _sema_count
            for _ in range(to_add):
                _sema.release()
                _sema_count += 1

threading.Thread(target=_refill, daemon=True).start()

def _acquire():
    global _sema_count
    _sema.acquire()
    with _sema_lock:
        _sema_count -= 1

def nvd_score(cve_id):
    req = urllib.request.Request(NVD_API.format(cve_id))
    if NVD_API_KEY:
        req.add_header('apiKey', NVD_API_KEY)
    _acquire()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        metrics = data['vulnerabilities'][0]['cve'].get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30'):
            m = metrics.get(key, [])
            if m:
                score = m[0]['cvssData']['vectorString']
                print(f"nve-score {cve_id} {score}")
                return cve_id, score
        return cve_id, None
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"NVD rate-limited {cve_id}")
        else:
            print(f"NVD HTTPError {e.code} for {cve_id}")
            return cve_id, None
    except Exception as ex:
        print(f"NVD exception for {cve_id}: {ex}")
        return cve_id, None
    return cve_id, 'retry'

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

scores = {c: None for c in cves}
summaries = {c: None for c in cves}

if os.path.exists(sys.argv[1]):
    with open(sys.argv[1]) as f:
        prev = json.load(f)
    for cve, score, summary in zip(prev['cve'], prev['cvss_score'], prev['summary']):
        if cve in scores:
            scores[cve] = score
            summaries[cve] = summary

need_nvd = [c for c in cves if scores[c] is None]
print(f"need-nvd {len(need_nvd)}/{len(cves)}")

with ThreadPoolExecutor(max_workers=RATE_LIMIT) as ex:
    futures = {ex.submit(nvd_score, c): c for c in need_nvd}
    while futures:
        for fut in as_completed(list(futures)):
            cve = futures.pop(fut)
            cve_id, score = fut.result()
            if score == 'retry':
                futures[ex.submit(nvd_score, cve_id)] = cve_id
            else:
                scores[cve_id] = score

with open(sys.argv[1], 'w') as f:
    json.dump({'cve': cves, 'cvss_score': [scores[c] for c in cves], 'summary': [summaries[c] for c in cves]}, f)
