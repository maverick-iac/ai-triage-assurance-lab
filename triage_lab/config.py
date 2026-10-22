"""Loads config/settings.yaml once and resolves paths relative to the repo root."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def settings() -> dict:
    with open(ROOT / "config" / "settings.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def path(key: str) -> Path:
    p = ROOT / settings()["paths"][key]
    p.mkdir(parents=True, exist_ok=True)
    return p
