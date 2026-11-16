"""qants-seed-apifetch: predicts whether a free public API call returns VALID data right now.

Task = "GET <endpoint> now". Success = HTTP 200 AND JSON parses AND the required field has the right type AND
total latency < LATENCY_MS. The agent declares P(success) BEFORE making the call. Predictor (fixed in advance):
per-endpoint Laplace estimate (successes+2)/(n+3) from this agent's own earlier calls in the run, clipped to [0.05, 0.95].
Calls are spaced (1 s) and the run is 5 rounds over all endpoints, low volume.
"""
import json, sys, time, urllib.request
from common import VERSION, UA, open_ledger, EventLog, sha

AGENT = "qants-seed-apifetch"
LATENCY_MS = 600
ROUNDS = 5
ENDPOINTS = [
    ("open-meteo-jerusalem", "https://api.open-meteo.com/v1/forecast?latitude=31.77&longitude=35.21&current=temperature_2m", ("current", "temperature_2m"), float),
    ("open-meteo-london", "https://api.open-meteo.com/v1/forecast?latitude=51.5&longitude=-0.12&current=temperature_2m", ("current", "temperature_2m"), float),
    ("wikipedia-summary", "https://en.wikipedia.org/api/rest_v1/page/summary/Python_(programming_language)", ("title",), str),
    ("jsonplaceholder-todo", "https://jsonplaceholder.typicode.com/todos/1", ("id",), int),
    ("httpbin-json", "https://httpbin.org/json", ("slideshow", "title"), str),
    ("dog-ceo", "https://dog.ceo/api/breeds/image/random", ("message",), str),
    ("catfact", "https://catfact.ninja/fact", ("fact",), str),
    ("coingecko-ping", "https://api.coingecko.com/api/v3/ping", ("gecko_says",), str),
    ("frankfurter-latest", "https://api.frankfurter.app/latest", ("rates",), dict),
    ("pokeapi-ditto", "https://pokeapi.co/api/v2/pokemon/ditto", ("name",), str),
]


def probe(url, path, typ):
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            status, body = r.status, r.read()
        ms = (time.perf_counter() - t0) * 1000
        d = json.loads(body)
        for k in path: d = d[k]
        ok = status == 200 and isinstance(d, typ) and not (typ is int and isinstance(d, bool)) and ms < LATENCY_MS
        return ok, status, round(ms), sha(body)
    except Exception as e:  # network error, timeout, bad JSON, missing field: all are real failures
        return False, type(e).__name__, round((time.perf_counter() - t0) * 1000), None


def main():
    led, log = open_ledger(AGENT), EventLog(AGENT)
    if led.receipts():
        sys.exit("ledger already has records for this seed; refusing to re-run")
    stats = {}
    for rnd in range(1, ROUNDS + 1):
        for name, url, path, typ in ENDPOINTS:
            s, n = stats.get(name, (0, 0))
            p = min(0.95, max(0.05, (s + 2) / (n + 3)))
            tid = f"{name}:round{rnd}"
            led.declare(tid, p, AGENT, VERSION)
            ok, status, ms, h = probe(url, path, typ)
            led.resolve(tid, ok, AGENT, VERSION)
            stats[name] = (s + int(ok), n + 1)
            log.add(event="probe", endpoint=name, round=rnd, ok=ok, status=status, ms=ms, body_sha256=h)
            time.sleep(1.0)
        time.sleep(20)
    print(json.dumps({k: v for k, v in led.summary(AGENT).items() if k != "reliability"}, indent=1))


if __name__ == "__main__":
    main()
