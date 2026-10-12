"""MITRE ATT&CK lookups from the bundled Enterprise matrix."""
from __future__ import annotations

import json
from functools import lru_cache

from ..config import BUNDLED_DATA

# ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment.
TACTIC_ALIASES = {"defense-evasion": "stealth"}


@lru_cache(maxsize=1)
def data() -> dict:
    return json.loads((BUNDLED_DATA / "attack_enterprise.json").read_text())


def tactics() -> list[dict]:
    return data()["tactics"]


def tactic_names() -> dict[str, str]:
    return {t["short"]: t["name"] for t in tactics()}


def technique(tid: str) -> dict | None:
    t = data()["techniques"].get(tid.upper())
    if t is None:
        return None
    parent = tid.split(".")[0].upper()
    return {"id": tid.upper(), "name": t["name"], "tactics": t.get("tactics", []),
            "parent": parent if "." in tid else None,
            "parent_name": data()["techniques"].get(parent, {}).get("name") if "." in tid else None,
            "url": f"https://attack.mitre.org/techniques/{tid.upper().replace('.', '/')}/"}


def resolve(techniques: list[str], tactic_tags: list[str]) -> tuple[list[str], list[dict]]:
    """Return (tactic short names, technique details) for a rule's tags."""
    names = tactic_names()
    techs = [t for t in (technique(tid) for tid in techniques) if t]
    # Prefer the rule author's tactic tags; fall back to every tactic of the techniques.
    tacs: list[str] = []
    for ta in tactic_tags:
        ta = TACTIC_ALIASES.get(ta, ta)
        if ta in names and ta not in tacs:
            tacs.append(ta)
    if not tacs:
        for t in techs:
            for ta in t["tactics"]:
                if ta not in tacs:
                    tacs.append(ta)
    order = [t["short"] for t in tactics()]
    tacs.sort(key=lambda x: order.index(x) if x in order else 99)
    return tacs, techs
