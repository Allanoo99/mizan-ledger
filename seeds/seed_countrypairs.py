"""qants-seed-countrypairs: answers binary questions in the Mizan pool format with free public data.

Question: "Does country A have a larger population than country B?" (yes/no, probability of yes).
Data: Wikidata SPARQL (public). Step 1 fetches ONLY areas (P2046); the agent then declares
p = sigmoid(K * ln(area_A / area_B)) with K = 0.45 fixed before the run (never tuned on outcomes).
Step 2 (after all declarations) fetches populations (P1082) and resolves. Both fetch times and body hashes are logged.
Countries with more than one value for area or population in the answer are dropped (no guessing).
Resolution source: Wikidata population value at the fetch time; it mixes census/estimate years, a known limitation.
"""
import json, math, random, sys, urllib.parse, urllib.request
from common import VERSION, UA, open_ledger, EventLog, sha

AGENT = "qants-seed-countrypairs"
K = 0.45
N_PAIRS = 60
SEED = 20261116
Q_AREA = 'SELECT ?c ?cLabel ?v WHERE { ?c wdt:P31 wd:Q6256 . ?c wdt:P2046 ?v . FILTER NOT EXISTS { ?c wdt:P576 ?end } SERVICE wikibase:label { bd:serviceParam wikibase:language "en". } }'
Q_POP = 'SELECT ?c ?v WHERE { ?c wdt:P31 wd:Q6256 . ?c wdt:P1082 ?v . FILTER NOT EXISTS { ?c wdt:P576 ?end } }'


def sparql(q, log, label):
    url = "https://query.wikidata.org/sparql?format=json&query=" + urllib.parse.quote(q)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/sparql-results+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    log.add(event="fetch", what=label, bytes=len(body), body_sha256=sha(body))
    rows = json.loads(body)["results"]["bindings"]
    by = {}
    for r in rows:
        by.setdefault(r["c"]["value"], []).append(r)
    return {k: v for k, v in by.items() if len(v) == 1}


def main():
    led, log = open_ledger(AGENT), EventLog(AGENT)
    if led.receipts():
        sys.exit("ledger already has records for this seed; refusing to re-run")
    area = sparql(Q_AREA, log, "areas")
    A = {k: (float(v[0]["v"]["value"]), v[0]["cLabel"]["value"]) for k, v in area.items() if float(v[0]["v"]["value"]) > 0}
    ids = sorted(A)
    rng = random.Random(SEED)
    pairs, used = [], set()
    while len(pairs) < N_PAIRS:
        a, b = rng.sample(ids, 2)
        if (a, b) in used or (b, a) in used: continue
        used.add((a, b)); pairs.append((a, b))
    declared = []
    for a, b in pairs:
        p = 1 / (1 + math.exp(-K * math.log(A[a][0] / A[b][0])))
        p = min(0.97, max(0.03, p))
        tid = f"pop:{a.rsplit('/',1)[1]}>{b.rsplit('/',1)[1]}"
        led.declare(tid, p, AGENT, VERSION)
        declared.append((tid, a, b))
    log.add(event="all_declared", n=len(declared))
    pop = sparql(Q_POP, log, "populations")
    P = {k: float(v[0]["v"]["value"]) for k, v in pop.items()}
    for tid, a, b in declared:
        if a in P and b in P and P[a] != P[b]:
            led.resolve(tid, P[a] > P[b], AGENT, VERSION)
        else:
            log.add(event="left_pending", task_hash=sha(tid.encode()), reason="population missing/ambiguous/tied")
    print(json.dumps({k: v for k, v in led.summary(AGENT).items() if k != "reliability"}, indent=1))


if __name__ == "__main__":
    main()
