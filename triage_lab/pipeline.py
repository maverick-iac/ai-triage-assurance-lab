"""Runs stages 2-6 end to end and records both arms for every incident.

  baseline     "AI alone": whatever the model decides is final
  assured      the same model answer, then the verifier (with one self-correction
               retry) and the gates decide (plus the critic's objection, if --critic)
  critic_only  (only with --critic) the model's answer plus an AI critic, no code gates:
               does an AI reviewer catch what the code gates catch?

All arms share the same triage call per incident, so the comparison is fair.

Modes:  evidence (code-built bundle) | payload (alerted events only) | agentic (the AI
investigates with read-only tools; see agentic.py)

Rows are written to results/runs/<name>.jsonl as each incident finishes, so a run
that stops halfway keeps its progress; --resume skips incidents already done.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .agent import Agent, retry_prompt
from .agentic import investigate
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
        limit: int | None = None, quiet: bool = False, critic: bool = False, resume: bool = False) -> list[dict]:
    events, lq, alerts, incidents = detection_stage()
    events_by_id = {e.id: e for e in events}
    alerts_by_id = {a.id: a for a in alerts}
    users = load_user_context()
    retriever = Retriever(poison=poison) if rag else None
    agent = Agent(backend, temperature, run_index)
    retries = settings()["gates"]["verifier_retries"]

    out = path("results_dir") / "runs"
    out.mkdir(parents=True, exist_ok=True)
    f = out / f"{name}.jsonl"
    done: dict[str, dict] = {}
    if resume and f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done[r.get("incident_key", r["incident_id"])] = r
    todo = incidents[:limit] if limit else incidents
    if not quiet and done:
        print(f"resuming '{name}': {len(done)} incidents already done")

    with open(f, "a" if resume else "w", encoding="utf-8") as fh:
        for n, inc in enumerate(todo, 1):
            key = f"{inc.user}|{inc.start}"          # stable even if new incidents shift the numbering
            if key in done:
                done[key]["incident_id"] = inc.id
                continue
            row = _triage_one(inc, agent, mode, context, rag, poison, critic, retries, events, events_by_id,
                              alerts_by_id, lq, users, retriever, name)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            row["incident_key"] = key
            done[key] = row
            if not quiet:
                extra = f" critic={row['critic_only']:<8}" if critic else ""
                tools = f" tools={len(row['trajectory'])}" if mode == "agentic" else ""
                print(f"[{n}/{len(todo)}] {inc.id} {inc.user:<11} baseline={row['baseline']:<8} "
                      f"assured={row['assured']:<8}{extra}{tools} {'; '.join(row['gate_reasons'])[:60]}")

    order = {i.id: k for k, i in enumerate(incidents)}
    rows = sorted(done.values(), key=lambda r: order.get(r["incident_id"], 1e9))
    with open(f, "w", encoding="utf-8") as fh:          # tidy final file, in incident order
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    return rows


def _triage_one(inc, agent, mode, context, rag, poison, critic, retries, events, events_by_id,
                alerts_by_id, lq, users, retriever, name) -> dict:
    def code_bundle(m="evidence"):
        return build_bundle(inc, alerts_by_id, events, events_by_id, lq, users, retriever,
                            mode=m, with_context=context)

    trajectory, invalid_calls, fallback, off_target = [], 0, False, 0
    if mode == "agentic":
        res = investigate(agent, inc, alerts_by_id, events, events_by_id, lq, users, retriever, context,
                          code_bundle)
        bundle, v0, raw0, secs = res["bundle"], res["verdict"], res["raw"], res["seconds"]
        trajectory, invalid_calls, fallback, off_target = (res["trajectory"], res["invalid_tool_calls"],
                                                           res["fallback"], res["off_target_calls"])
    else:
        bundle = code_bundle(mode)
        v0, raw0, secs = agent.triage(bundle)
    c0 = verify(v0, bundle) if v0 else None
    baseline = v0["decision"] if v0 else "escalate"

    v, c, used_retry = v0, c0, False
    if v0 and c0 and not c0["passed"] and retries:
        history = [{"role": "assistant", "content": raw0},
                   {"role": "user", "content": retry_prompt(c0["failures"], bundle, v0)}]
        v1, _, s1 = agent.triage(bundle, history)
        secs += s1
        used_retry = True
        if v1:
            v, c = v1, verify(v1, bundle)
    assured, reasons = apply_gates(v, c, bundle)

    crit, crit_valid, critic_only = None, False, baseline
    if critic and v0 and v0["decision"] == "close":
        crit, cs = agent.critique(bundle, v0)
        secs += cs
        if crit and crit["objection"]:
            claim = {"claims": [{"type": "observed", "text": crit["argument"], "event_ids": crit["event_ids"],
                                 "quote": crit["quote"]}]}
            crit_valid = verify(claim, bundle)["passed"]
        if crit_valid:
            critic_only = "escalate"
            if assured == "close":
                assured = "escalate"
            reasons = reasons + [f"critic objection: {crit['argument'][:80]}"]

    return {
        "run": name, "incident_id": inc.id, "user": inc.user, "backend": agent.label,
        "mode": mode, "context": context, "rag": rag, "poison": poison, "critic": critic,
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
        **({"critic_only": critic_only, "critic_review": crit, "critic_objection_valid": crit_valid}
           if critic else {}),
        "trajectory": trajectory, "invalid_tool_calls": invalid_calls, "agentic_fallback": fallback,
        "off_target_tool_calls": off_target,
        "bundle_event_ids": [e["id"] for e in bundle["events"]],
        "seconds": secs, "log_health": bundle["log_health"],
        "rag_docs": [k["doc"] for k in bundle["knowledge"]],
    }
