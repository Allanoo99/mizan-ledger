"""Build the public, hash-only summary of the seed agents (counts and scores, no task content) from the local ledgers.
Every ledger is verified offline first; the export refuses to run if any ledger fails verification."""
import json, sys, datetime as dt
from common import ROOT, RUNS
from mizan_ledger import verify_ledger_dir

AGENTS = [
    ("qants-seed-codetask", "Code-task agent", "وكيل مهام برمجية",
     "Predicts whether the project's own unit tests stay green after a small code change, then runs them.",
     "يتوقع هل تبقى اختبارات الوحدة للمشروع ناجحة بعد تعديل صغير على الشيفرة، ثم يشغّلها."),
    ("qants-seed-apifetch", "API-fetch agent", "وكيل جلب واجهات",
     "Predicts whether a free public API call returns valid data within a time limit, then makes the call.",
     "يتوقع هل يعيد استدعاء واجهة عامة مجانية بيانات صالحة ضمن حد زمني، ثم ينفّذ الاستدعاء."),
    ("qants-seed-countrypairs", "Pool-format agent", "وكيل بصيغة البركة",
     "Answers yes/no questions in the Mizan pool format from free public data (Wikidata), then checks them.",
     "يجيب عن أسئلة نعم/لا بصيغة بركة الميزان من بيانات عامة مجانية (Wikidata)، ثم يتحقق منها."),
]
out_agents, tot_d, tot_r = [], 0, 0
for aid, en, ar, den, dar in AGENTS:
    rep = verify_ledger_dir(RUNS / aid)
    if not rep["ok"]:
        sys.exit(f"{aid}: verification failed: {rep['errors'][:3]}")
    s = rep["summary"]
    out_agents.append({
        "agent_id": aid, "kind_en": en, "kind_ar": ar, "does_en": den, "does_ar": dar, "agent_version": "0.1.0",
        "operator": "QANTS", "counts_as_external": False,
        "declared": s["declared"], "resolved": s["resolved"], "pending": s["pending"],
        "base_rate": round(s["base_rate"], 4), "brier": round(s["brier"], 4),
        "brier_ci95": [round(x, 4) for x in s["brier_ci95"]], "brier_always_0_5": 0.25,
        "ece": round(s["ece"], 4), "log_loss": round(s["log_loss"], 4),
        "ledger_verified_offline": True, "receipt_chain_head": rep["chain_heads"]["receipt_head"],
    })
    tot_d += s["declared"]; tot_r += s["resolved"]
doc = {
    "schema": "qants-seed-agents/1",
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "label": "QANTS-operated seed agents. Not external agents. Counted separately from the external counter.",
    "seed_agents": len(out_agents), "declarations": tot_d, "resolved": tot_r,
    "agents": out_agents,
    "limits": "Small samples; wide intervals. Declared before each outcome was fetched; hash-only receipts; clocks are local until the chain head is anchored. Seeds never use the production Mizan API. No prediction content is published here.",
}
dest = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "seed_runs" / "seed_agents_public.json")
json.dump(doc, open(dest, "w"), indent=1, ensure_ascii=False)
print(dest, tot_d, tot_r)
