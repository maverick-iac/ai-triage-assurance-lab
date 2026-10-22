"""Command line: python -m triage_lab <command> [options]

  generate                 build the labelled dataset (stage 1)
  run                      one experiment: stages 2-6 for every incident
  stage <name>             a named batch of runs (what the Kaggle notebook uses), always resumable:
                             main | ablations | agentic | bigger_model | repeat | gaploop | score | all
  ablations                payload-only, no-context, no-RAG and poisoned-RAG runs
  repeat                   k repeated runs for the consistency metric (pass^k)
  score                    stage 7: metrics.json + REPORT.md + Navigator layer
  demo                     the demo script
  gaploop                  draft, backtest and refine rules for missed techniques
  cases                    write a readable handover case file per incident (results/cases/<run>/)
  ingest-windows           add live Atomic Red Team / Sysmon events
  all                      generate + every run + gaploop + score + demo

Common options: --backend stub|ollama|replay   --model qwen2.5:7b   --resume
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# every named experiment: run name -> options
RUNS = {
    "main": {},
    "payload_only": {"mode": "payload"},
    "no_context": {"context": False},
    "no_rag": {"rag": False},
    "poisoned_rag": {"poison": True},
    "main_critic": {"critic": True},
    "agentic": {"mode": "agentic"},
    "agentic_critic": {"mode": "agentic", "critic": True},
}
STAGES = {
    "main": ["main"],
    "ablations": ["payload_only", "no_context", "no_rag", "poisoned_rag"],
    "agentic": ["agentic", "agentic_critic", "main_critic"],
    "bigger_model": ["main", "agentic"],
}


def _tag(model: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", model.lower()).strip("-")


def main(argv: list[str] | None = None) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", choices=["stub", "ollama", "replay"])
    common.add_argument("--model", help="override agent.model, e.g. qwen2.5:7b")
    common.add_argument("--resume", action="store_true", help="skip incidents already finished in a run")

    p = argparse.ArgumentParser(prog="triage_lab", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate")

    r = sub.add_parser("run", parents=[common])
    r.add_argument("--name", default="main")
    r.add_argument("--mode", choices=["evidence", "payload", "agentic"], default="evidence")
    r.add_argument("--no-context", action="store_true")
    r.add_argument("--no-rag", action="store_true")
    r.add_argument("--poison", action="store_true")
    r.add_argument("--critic", action="store_true", help="add the critic agent")
    r.add_argument("--limit", type=int, help="only the first N incidents (quick test)")

    st = sub.add_parser("stage", parents=[common])
    st.add_argument("name", choices=list(STAGES) + ["repeat", "gaploop", "score", "all"])
    st.add_argument("-k", type=int, default=3, help="repeats for the repeat stage")
    st.add_argument("--limit", type=int)

    a = sub.add_parser("ablations", parents=[common])
    a.add_argument("--only", nargs="*", choices=list(RUNS))
    k = sub.add_parser("repeat", parents=[common])
    k.add_argument("-k", type=int, default=3)
    k.add_argument("--temperature", type=float, default=0.7)
    sub.add_parser("score")
    d = sub.add_parser("demo")
    d.add_argument("--run", default="main")
    sub.add_parser("gaploop", parents=[common])
    cs = sub.add_parser("cases")
    cs.add_argument("--run", nargs="*", help="run names (default: every run)")
    w = sub.add_parser("ingest-windows")
    w.add_argument("--events", required=True)
    w.add_argument("--labels", required=True)
    w.add_argument("--shift-to")
    w.add_argument("--as-user")
    sub.add_parser("all", parents=[common])

    args = p.parse_args(argv)
    if getattr(args, "model", None):
        from .config import override
        override("agent.model", args.model)
    backend, resume = getattr(args, "backend", None), getattr(args, "resume", False)

    if args.cmd in ("generate", "all"):
        from .generate import main as gen
        gen()
    if args.cmd == "run":
        from .pipeline import run
        run(args.name, backend, args.mode, not args.no_context, not args.no_rag, args.poison,
            limit=args.limit, critic=args.critic, resume=resume)
    if args.cmd == "ablations":
        _runs(args.only or STAGES["ablations"], backend, resume)
    if args.cmd == "all":
        _runs(list(RUNS), backend, resume)
    if args.cmd == "repeat":
        _repeat(backend, args.k, args.temperature, resume)
    if args.cmd == "stage":
        _stage(args, backend)
    if args.cmd in ("gaploop", "all"):
        from .gaploop import run as gap
        for r in gap(backend):
            print(json.dumps(r, default=str))
    if args.cmd in ("score", "all", "repeat"):
        _score()
    if args.cmd in ("demo", "all"):
        from .demo import main as demo
        print(demo(getattr(args, "run", "main")))
    if args.cmd == "cases":
        _cases(args.run)
    if args.cmd == "ingest-windows":
        from pathlib import Path

        from .ingest.windows import ingest
        print(ingest(Path(args.events), Path(args.labels), args.shift_to, args.as_user))


def _runs(names: list[str], backend, resume: bool, suffix: str = "", limit: int | None = None) -> None:
    from .pipeline import run
    for name in names:
        print(f"\n--- run: {name + suffix} {RUNS[name] or ''}")
        run(name + suffix, backend, quiet=False, resume=resume, limit=limit, **RUNS[name])


def _repeat(backend, k: int, temperature: float, resume: bool) -> None:
    from .pipeline import run
    for i in range(k):
        print(f"--- repeat {i + 1}/{k}")
        run(f"repeat_{i + 1}", backend, temperature=temperature, run_index=i + 1, quiet=True, resume=resume)


def _stage(args, backend) -> None:
    from .config import path, settings
    if not (path("data_dir") / "events.jsonl").exists():
        from .generate import main as gen
        gen()
    if args.name in STAGES:
        suffix = f"__{_tag(settings()['agent']['model'])}" if args.name == "bigger_model" else ""
        _runs(STAGES[args.name], backend, resume=True, suffix=suffix, limit=args.limit)
    elif args.name == "repeat":
        _repeat(backend, args.k, 0.7, resume=True)
    elif args.name == "gaploop":
        from .gaploop import run as gap
        for r in gap(backend):
            print(json.dumps(r, default=str))
    elif args.name == "all":
        for s in ("main", "ablations", "agentic"):
            _runs(STAGES[s], backend, resume=True, limit=args.limit)
        from .gaploop import run as gap
        gap(backend)
    _score()


def _score() -> None:
    from .config import path
    from .metrics import score
    from .navigator import export
    from .report import write
    runs_dir = path("results_dir") / "runs"
    present = {p.stem for p in runs_dir.glob("*.jsonl")}
    names = [n for n in RUNS if n in present] + sorted(n for n in present
                                                        if n not in RUNS and not n.startswith("repeat_"))
    repeats = sorted(n for n in present if n.startswith("repeat_"))
    m = score(names, repeats or None)
    export(m)
    write(m)
    _cases(names, quiet=True)
    print(f"Wrote results/metrics.json, results/REPORT.md, results/navigator_layer.json "
          f"({len(names)} runs scored{', ' + str(len(repeats)) + ' repeats' if repeats else ''})")


def _cases(names=None, quiet: bool = False) -> None:
    from .casefile import write_cases
    from .config import path
    runs_dir = path("results_dir") / "runs"
    names = names or sorted(p.stem for p in runs_dir.glob("*.jsonl") if not p.stem.startswith("repeat_"))
    for n in names:
        k = write_cases(n)
        if not quiet:
            print(f"wrote {k} case files to results/cases/{n}/")


if __name__ == "__main__":
    main(sys.argv[1:])
