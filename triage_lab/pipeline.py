"""Runs stages 2-6 end to end and records both arms for every incident.

  baseline  "AI alone": whatever the model decides is final
  assured   the same model answer, then the verifier (with one self-correction
            retry) and the gates decide

Both arms share ONE model call per incident, so the comparison is fair: the
only difference is the controls.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .agent import Agent, retry_prompt
from .config import path, settings
from .correlate import correlate
from .detections import detect
from .evidence import build_bundle, load_user_context
from .gates import apply_gates
from .log_quality import LogQuality
from .rag import Retriever
from .schema import load_events
from .verifier import verify


def detection_stage():
    events, stats = load_events(path("data_dir") / "events.jsonl")
    lq = LogQuality(events, stats)
    alerts = detect(events)
    incidents = correlate(alerts)
    out = path("results_dir") / "pipeline"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "alerts.jsonl", "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(asdict(a)) + "\n" for a in alerts)
    with open(out / "incidents.jsonl", "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(asdict(i)) + "\n" for i in incidents)
    with open(out / "log_quality.jsonl", "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in lq.table())
    (out / "parse_stats.json").write_text(json.dumps({**stats, "lag_p95_seconds": lq.lag_p95,
                                                      "parse_rate": lq.parse_rate}, indent=2))
    return events, lq, alerts, incidents


def run(name: str = "main", backend: str | None = None, mode: str = "evidence", context: bool = True,
        rag: bool = True, poison: bool = False, temperature: float | None = None, run_index: int = 0,
        limit: int | None = None, quiet: bool = False) -> list[dict]:
    events, lq, alerts, incidents = detection_stage()
    events_by_id = {e.id: e for e in events}
    alerts_by_id = {a.id: a for a in alerts}
    users = load_user_context()
    retriever = Retriever(poison=poison) if rag else None
    agent = Agent(backend, temperature, run_index)
    retries = settings()["gates"]["verifier_retries"]

    rows = []
    todo = incidents[:limit] if limit else incidents
    for n, inc in enumerate(todo, 1):
        bundle = build_bundle(inc, alerts_by_id, events, events_by_id, lq, users, retriever,
                              mode=mode, with_context=context)
        v0, raw0, secs = agent.triage(bundle)
        c0 = verify(v0, bundle) if v0 else None
        baseline = v0["decision"] if v0 else "escalate"

        v, c, used_retry = v0, c0, False
        if v0 and c0 and not c0["passed"] and retries:
            history = [{"role": "assistant", "content": raw0},
                       {"role": "user", "content": retry_prompt(c0["failures"])}]
            v1, _, s1 = agent.triage(bundle, history)
            secs += s1
            used_retry = True
            if v1:
                v, c = v1, verify(v1, bundle)
        assured, reasons = apply_gates(v, c, bundle)

        rows.append({
            "run": name, "incident_id": inc.id, "user": inc.user, "backend": agent.label,
            "mode": mode, "context": context, "rag": rag, "poison": poison,
            "techniques_detected": inc.techniques, "risk": inc.risk,
            "schema_valid": v0 is not None, "model_decision": baseline,
            "model_confidence": v0["confidence"] if v0 else None,
            "model_techniques": v0.get("techniques", []) if v0 else [],
            "context_used": v0.get("context_used", []) if v0 else [],
            "not_determinable": v0.get("not_determinable", []) if v0 else [],
            "summary": v0.get("summary", "") if v0 else raw0[:300],
            "check_first": c0, "check_final": c, "retried": used_retry,
            "final_model_decision": v["decision"] if v else "escalate",
            "baseline": baseline, "assured": assured, "gate_reasons": reasons,
            "seconds": secs, "log_health": bundle["log_health"],
            "rag_docs": [k["doc"] for k in bundle["knowledge"]],
        })
        if not quiet:
            print(f"[{n}/{len(todo)}] {inc.id} {inc.user:<11} baseline={baseline:<8} "
                  f"assured={assured:<8} {'; '.join(reasons)[:70]}")

    out = path("results_dir") / "runs"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / f"{name}.jsonl", "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    return rows
