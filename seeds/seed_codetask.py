"""qants-seed-codetask: a code-task agent that predicts whether its own unit tests stay green.

Task = "apply patch M to the mizan-ledger source; will the project's test suite still pass?".
The patches are mechanical single-site mutations (comparison flip, +/- swap, constant+1, and/or swap, not-removal).
The agent declares P(suite still passes) BEFORE running the tests, then runs them in a throw-away copy.
Predictor (fixed before the run, updated only from earlier results):
  * line not executed by the suite  -> Beta(9,1) prior for 'survives'
  * line executed by the suite      -> Beta(1,3) prior per mutation kind, updated online with prior results
"""
import ast, json, os, random, shutil, subprocess, sys, tempfile
from pathlib import Path
from common import ROOT, VERSION, open_ledger, EventLog, sha

AGENT = "qants-seed-codetask"
TARGETS = ["core.py", "metrics.py"]
N_TASKS = 60
SEED = 20261116

CMP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq}
ARITH = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div, ast.Div: ast.Mult}


def sites(tree):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and type(node.ops[0]) in CMP: out.append((node, "cmp"))
        elif isinstance(node, ast.BinOp) and type(node.op) in ARITH: out.append((node, "arith"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool): out.append((node, "const"))
        elif isinstance(node, ast.BoolOp): out.append((node, "boolop"))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not): out.append((node, "not"))
    return out


def mutate(src: str, idx: int) -> str:
    tree = ast.parse(src)
    node, kind = sites(tree)[idx]
    if kind == "cmp": node.ops[0] = CMP[type(node.ops[0])]()
    elif kind == "arith": node.op = ARITH[type(node.op)]()
    elif kind == "const": node.value = node.value + 1
    elif kind == "boolop": node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "not": node.__class__ = ast.Constant; node.value = True; node.kind = None  # drop the `not` -> truthy constant would change meaning; replaced below
    return ast.unparse(ast.fix_missing_locations(tree))


def mutate_not(src: str, idx: int) -> str:
    tree = ast.parse(src)
    target, kind = sites(tree)[idx]
    class T(ast.NodeTransformer):
        def visit_UnaryOp(self, n):
            self.generic_visit(n)
            return n.operand if n is target else n
    return ast.unparse(ast.fix_missing_locations(T().visit(tree)))


def do_mutate(src, idx):
    kind = sites(ast.parse(src))[idx][1]
    return mutate_not(src, idx) if kind == "not" else mutate(src, idx)


def run_suite(work: Path, timeout=60):
    env = dict(os.environ, PYTHONPATH=str(work / "src"), PYTHONDONTWRITEBYTECODE="1")
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", str(work / "tests")],
                           cwd=work, env=env, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def covered_lines(work: Path):
    """Executed lines of src/mizan_ledger/*.py while the suite runs (sys.settrace in a subprocess)."""
    runner = work / "_cov.py"
    runner.write_text(
        "import sys, json, pytest\n"
        f"root = {str(work / 'src' / 'mizan_ledger')!r}\n"
        "hit = set()\n"
        "def tr(frame, ev, arg):\n"
        "    f = frame.f_code.co_filename\n"
        "    if not f.startswith(root): return None\n"
        "    def lt(fr, e, a):\n"
        "        if e == 'line': hit.add((f.rsplit('/',1)[1], fr.f_lineno))\n"
        "        return lt\n"
        "    hit.add((f.rsplit('/',1)[1], frame.f_lineno))\n"
        "    return lt\n"
        "sys.settrace(tr)\n"
        f"rc = pytest.main(['-q','-p','no:cacheprovider', {str(work / 'tests')!r}])\n"
        "sys.settrace(None)\n"
        f"json.dump(sorted(hit), open({str(work / '_cov.json')!r}, 'w'))\n"
        "sys.exit(rc)\n")
    env = dict(os.environ, PYTHONPATH=str(work / "src"), PYTHONDONTWRITEBYTECODE="1")
    subprocess.run([sys.executable, str(runner)], cwd=work, env=env, capture_output=True, timeout=300)
    return {(f, l) for f, l in json.loads((work / "_cov.json").read_text())}


def main():
    led, log = open_ledger(AGENT), EventLog(AGENT)
    if led.receipts():
        sys.exit("ledger already has records for this seed; refusing to re-run")
    work = Path(tempfile.mkdtemp(prefix="seed_codetask_"))
    for d in ("src", "tests", "vectors"):
        shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))
    assert run_suite(work), "baseline suite must be green before mutating"
    cov = covered_lines(work)
    log.add(event="baseline_green_and_coverage", covered_lines=len(cov))

    pool = []
    for fn in TARGETS:
        src = (work / "src/mizan_ledger" / fn).read_text()
        for i, (node, kind) in enumerate(sites(ast.parse(src))):
            # coverage is measured on the original file layout, so use line numbers of the original source
            pool.append({"file": fn, "idx": i, "kind": kind, "line": node.lineno})
    random.Random(SEED).shuffle(pool)
    tasks = pool[:N_TASKS]
    log.add(event="task_pool", sites_total=len(pool), sampled=len(tasks), seed=SEED)

    counts = {}  # (covered, kind) -> [survived, n]
    for t in tasks:
        covered = (t["file"], t["line"]) in cov
        key = (covered, t["kind"])
        a0, b0 = (9, 1) if not covered else (1, 3)
        s, n = counts.get(key, [0, 0])
        p = min(0.97, max(0.03, (a0 + s) / (a0 + b0 + n)))
        tid = f"mutant:{t['file']}:site{t['idx']}:{t['kind']}:L{t['line']}"
        led.declare(tid, p, AGENT, VERSION)
        # --- only now run the suite on the mutated copy ---
        orig = work / "src/mizan_ledger" / t["file"]
        text = orig.read_text()
        orig.write_text(do_mutate(text, t["idx"]))
        try:
            survived = run_suite(work)
        finally:
            orig.write_text(text)
        led.resolve(tid, survived, AGENT, VERSION)
        s, n = counts.get(key, [0, 0]); counts[key] = [s + (1 if survived else 0), n + 1]
        log.add(event="resolved", task_hash=sha(tid.encode()), covered=covered, kind=t["kind"], survived=survived)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps(led.summary(AGENT), indent=1)[:1200])


if __name__ == "__main__":
    main()
