"""Command line: python -m triage_lab <command> [options]

  generate                 build the labelled dataset (stage 1)
  run                      stages 2-6 for every incident, both arms (one experiment)
  ablations                main run + payload-only, no-context, no-RAG and poisoned-RAG runs
  repeat                   k repeated runs for the consistency metric (pass^k)
  score                    stage 7: metrics.json + REPORT.md + Navigator layer
  demo                     the 28 October demo script
  gaploop                  draft and backtest rules for missed techniques
  ingest-windows           add live Atomic Red Team / Sysmon events
  all                      generate + ablations + gaploop + score + demo
"""

from __future__ import annotations

import argparse
import json
import sys

ABLATIONS = {
    "main": {},
    "payload_only": {"mode": "payload"},
    "no_context": {"context": False},
    "no_rag": {"rag": False},
    "poisoned_rag": {"poison": True},
}


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="triage_lab", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate")

    r = sub.add_parser("run")
    r.add_argument("--name", default="main")
    r.add_argument("--backend", choices=["stub", "ollama", "replay"])
    r.add_argument("--mode", choices=["evidence", "payload"], default="evidence")
    r.add_argument("--no-context", action="store_true")
    r.add_argument("--no-rag", action="store_true")
    r.add_argument("--poison", action="store_true")
    r.add_argument("--limit", type=int, help="only the first N incidents (quick test)")

    a = sub.add_parser("ablations")
    a.add_argument("--backend", choices=["stub", "ollama", "replay"])
    a.add_argument("--only", nargs="*", choices=list(ABLATIONS))

    k = sub.add_parser("repeat")
    k.add_argument("--backend", choices=["stub", "ollama", "replay"])
    k.add_argument("-k", type=int, default=3)
    k.add_argument("--temperature", type=float, default=0.7)

    sub.add_parser("score")
    d = sub.add_parser("demo")
    d.add_argument("--run", default="main")
    g = sub.add_parser("gaploop")
    g.add_argument("--backend", choices=["stub", "ollama", "replay"])
    w = sub.add_parser("ingest-windows")
    w.add_argument("--events", required=True)
    w.add_argument("--labels", required=True)
    w.add_argument("--shift-to")
    w.add_argument("--as-user")
    al = sub.add_parser("all")
    al.add_argument("--backend", choices=["stub", "ollama", "replay"])

    args = p.parse_args(argv)

    if args.cmd in ("generate", "all"):
        from .generate import main as gen
        gen()
    if args.cmd == "run":
        from .pipeline import run
        run(args.name, args.backend, args.mode, not args.no_context, not args.no_rag, args.poison,
            limit=args.limit)
    if args.cmd in ("ablations", "all"):
        from .pipeline import run
        for name, kw in ABLATIONS.items():
            if getattr(args, "only", None) and name not in args.only:
                continue
            print(f"\n--- run: {name} {kw or ''}")
            run(name, args.backend, quiet=True, **kw)
    if args.cmd == "repeat":
        from .pipeline import run
        for i in range(args.k):
            print(f"--- repeat {i + 1}/{args.k}")
            run(f"repeat_{i + 1}", args.backend, temperature=args.temperature, run_index=i + 1, quiet=True)
    if args.cmd in ("gaploop", "all"):
        from .gaploop import run as gap
        for r in gap(args.backend):
            print(json.dumps(r, default=str))
    if args.cmd in ("score", "all", "repeat"):
        _score()
    if args.cmd in ("demo", "all"):
        from .demo import main as demo
        print(demo(getattr(args, "run", "main")))
    if args.cmd == "ingest-windows":
        from pathlib import Path

        from .ingest.windows import ingest
        print(ingest(Path(args.events), Path(args.labels), args.shift_to, args.as_user))


def _score() -> None:
    from .config import path
    from .metrics import score
    from .navigator import export
    from .report import write
    runs_dir = path("results_dir") / "runs"
    names = [n for n in ABLATIONS if (runs_dir / f"{n}.jsonl").exists()]
    repeats = sorted(p.stem for p in runs_dir.glob("repeat_*.jsonl"))
    m = score(names, repeats or None)
    export(m)
    write(m)
    print(f"Wrote results/metrics.json, results/REPORT.md, results/navigator_layer.json "
          f"({len(names)} runs scored)")


if __name__ == "__main__":
    main(sys.argv[1:])
