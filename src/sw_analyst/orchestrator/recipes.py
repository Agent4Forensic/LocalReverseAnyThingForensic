"""Recipe loading: YAML in src/sw_analyst/recipes/. A recipe turns a detected file type into planned tasks."""
from __future__ import annotations

from pathlib import Path

import yaml

RECIPE_DIR = Path(__file__).resolve().parent.parent / "recipes"
_SCRIPT_TYPES = {"powershell", "vbscript", "javascript", "python", "bash", "batch", "html"}


def recipe_id_for(detected_type: str) -> str:
    t = (detected_type or "unknown").lower()
    if t == "pe":
        return "exe"
    if t in ("apk",):
        return "apk"
    if t in _SCRIPT_TYPES:
        return "script"
    return "generic"


def load_recipe(recipe_id: str) -> dict:
    path = RECIPE_DIR / f"{recipe_id}.yaml"
    if not path.is_file():
        path = RECIPE_DIR / "generic.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "steps" not in data:
        raise ValueError(f"invalid recipe file: {path.name}")
    return data
