"""Sigma correlation rules (Sigma specification v2).

    correlation:
      type: event_count | value_count | temporal | temporal_ordered
      rules: [base rule names or ids]
      group-by: [fields]
      timespan: 10m
      condition: {gte: 5}            # value_count also takes field: <name>
      aliases: {alias: {rule: field}}   # optional per-rule field renames
    generate: false                   # whether base rules also alert

Correlations can reference other correlations, which is how multi-stage
chains such as "brute force -> successful login -> sudo to root" are built.
State is kept in memory, bounded per group and pruned by timespan.
"""
from __future__ import annotations

import re
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .sigma import LEVELS, SigmaError, _field_values, _to_str

TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
MAX_PER_GROUP = 5000


def parse_timespan(s: Any) -> float:
    if isinstance(s, (int, float)):
        return float(s)
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw]?)\s*", str(s))
    if not m:
        raise SigmaError(f"bad timespan {s!r}")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def _cond_ok(cond: dict, value: float) -> bool:
    value = float(value)
    checks = {"gt": value.__gt__, "gte": value.__ge__, "lt": value.__lt__, "lte": value.__le__, "eq": value.__eq__}
    ok = True
    for k, fn in checks.items():
        if k in cond:
            ok = ok and fn(float(cond[k]))
    if "range" in cond:
        lo, _, hi = str(cond["range"]).partition("..")
        ok = ok and float(lo) <= value <= float(hi)
    return ok


@dataclass
class CorrelationRule:
    id: str
    title: str
    level: str
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: float
    condition: dict
    tags: list[str]
    path: str
    description: str = ""
    name: str | None = None
    generate: bool = False
    aliases: dict = field(default_factory=dict)
    error: str | None = None
    enabled: bool = True
    status: str = "experimental"
    author: str = ""
    falsepositives: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return [m.group(1).upper() for t in self.tags if (m := re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t, re.I))]

    @property
    def tactics(self) -> list[str]:
        return [m.group(1).replace("_", "-").lower() for t in self.tags
                if (m := re.match(r"^attack\.([a-z][a-z_-]+)$", t, re.I))]

    def summary(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "status": self.status,
                "description": self.description, "tags": self.tags, "techniques": self.techniques,
                "tactics": self.tactics, "logsource": {}, "path": self.path, "error": self.error,
                "enabled": self.enabled, "name": self.name, "type": "correlation",
                "correlation": {"type": self.type, "rules": self.rules, "group-by": self.group_by,
                                "timespan": self.timespan, "condition": self.condition},
                "author": self.author, "falsepositives": self.falsepositives, "references": []}


def compile_correlation(doc: dict, path: str = "") -> CorrelationRule:
    c = doc.get("correlation") or {}
    level = str(doc.get("level") or "high").lower()
    rule = CorrelationRule(
        id=str(doc.get("id") or doc.get("name") or doc.get("title")), title=str(doc.get("title") or "correlation"),
        level=level if level in LEVELS else "high", type=str(c.get("type") or ""),
        rules=[str(r) for r in (c.get("rules") or [])], group_by=[str(g) for g in (c.get("group-by") or [])],
        timespan=0, condition=dict(c.get("condition") or {}), tags=[str(t) for t in doc.get("tags") or []],
        path=path, description=str(doc.get("description") or "").strip(), name=doc.get("name"),
        generate=bool(c.get("generate", doc.get("generate", False))), aliases=dict(c.get("aliases") or {}),
        status=str(doc.get("status") or "experimental"), author=str(doc.get("author") or ""),
        falsepositives=[str(x) for x in doc.get("falsepositives") or []])
    try:
        if rule.type not in TYPES:
            raise SigmaError(f"unsupported correlation type {rule.type!r}")
        if not rule.rules:
            raise SigmaError("correlation without rules")
        rule.timespan = parse_timespan(c.get("timespan") or c.get("timeframe") or "5m")
        if rule.type in ("event_count", "value_count") and not rule.condition:
            raise SigmaError("missing condition")
        if rule.type == "value_count" and not rule.condition.get("field"):
            raise SigmaError("value_count needs condition.field")
    except SigmaError as exc:
        rule.error = str(exc)
    return rule


@dataclass
class Hit:
    """A base-rule (or correlation) match flowing into the correlation engine."""
    rule_keys: tuple[str, ...]   # names/ids the matched rule can be referenced by
    ts: float
    event: dict
    event_ids: list[int]


@dataclass
class CorrelationMatch:
    rule: CorrelationRule
    group: dict
    first_ts: float
    last_ts: float
    event_ids: list[int]
    event: dict          # the last contributing event, merged with group fields
    details: dict


class CorrelationEngine:
    def __init__(self, rules: list[CorrelationRule]):
        self.rules = [r for r in rules if not r.error]
        self._lock = threading.Lock()
        # rule.id -> group key -> deque[(ts, rule_ref, value, event_ids, event)]
        self._state: dict[str, dict[tuple, deque]] = defaultdict(dict)
        self._by_ref: dict[str, list[CorrelationRule]] = defaultdict(list)
        for r in self.rules:
            for ref in r.rules:
                self._by_ref[ref].append(r)

    def referenced(self) -> set[str]:
        return set(self._by_ref)

    def _group_values(self, rule: CorrelationRule, ref: str, ev: dict) -> tuple | None:
        vals = []
        for g in rule.group_by:
            fname = g
            alias = rule.aliases.get(g)
            if isinstance(alias, dict) and ref in alias:
                fname = alias[ref]
            v = _field_values(ev, fname)
            if not v or v[0] in (None, ""):
                return None
            vals.append(_to_str(v[0]))
        return tuple(vals)

    def process(self, hit: Hit, _depth: int = 0) -> list[CorrelationMatch]:
        out: list[CorrelationMatch] = []
        seen: set[str] = set()
        for ref in hit.rule_keys:
            for rule in self._by_ref.get(ref, []):
                if rule.id in seen or not rule.enabled:
                    continue
                seen.add(rule.id)
                m = self._feed(rule, ref, hit)
                if m:
                    out.append(m)
        if _depth < 4:  # chained correlations
            for m in list(out):
                keys = tuple(k for k in (m.rule.name, m.rule.id) if k)
                out.extend(self.process(Hit(keys, m.last_ts, m.event, m.event_ids), _depth + 1))
        return out

    def _feed(self, rule: CorrelationRule, ref: str, hit: Hit) -> CorrelationMatch | None:
        key = self._group_values(rule, ref, hit.event)
        if key is None:
            return None
        value = None
        if rule.type == "value_count":
            fname = rule.condition["field"]
            alias = rule.aliases.get(fname)
            if isinstance(alias, dict) and ref in alias:
                fname = alias[ref]
            v = _field_values(hit.event, fname)
            if not v or v[0] in (None, ""):
                return None
            value = _to_str(v[0])
        with self._lock:
            groups = self._state[rule.id]
            dq = groups.get(key)
            if dq is None:
                dq = groups[key] = deque(maxlen=MAX_PER_GROUP)
            dq.append((hit.ts, ref, value, hit.event_ids, hit.event))
            newest = max(x[0] for x in dq)
            while dq and dq[0][0] < newest - rule.timespan:
                dq.popleft()
            fired, details = self._evaluate(rule, dq)
            if not fired:
                return None
            items = list(dq)
            dq.clear()
        group = dict(zip(rule.group_by, key, strict=True))
        ev = dict(items[-1][4])
        ev.update(group)
        ids: list[int] = []
        for it in items:
            for i in it[3]:
                if i not in ids:
                    ids.append(i)
        return CorrelationMatch(rule, group, min(i[0] for i in items), max(i[0] for i in items), ids[-500:], ev, details)

    def _evaluate(self, rule: CorrelationRule, dq: deque) -> tuple[bool, dict]:
        if rule.type == "event_count":
            n = len(dq)
            return _cond_ok(rule.condition, n), {"event_count": n}
        if rule.type == "value_count":
            distinct = {x[2] for x in dq}
            n = len(distinct)
            return _cond_ok(rule.condition, n), {"value_count": n, "field": rule.condition["field"],
                                                 "values": sorted(distinct)[:50]}
        refs_needed = rule.rules
        if rule.type == "temporal":
            present = {x[1] for x in dq}
            ok = all(r in present for r in refs_needed)
            return ok, {"sequence": [x[1] for x in dq][-20:]}
        # temporal_ordered: each referenced rule appears after the previous one
        idx = 0
        for item in sorted(dq, key=lambda x: x[0]):
            if idx < len(refs_needed) and item[1] == refs_needed[idx]:
                idx += 1
        return idx == len(refs_needed), {"sequence": refs_needed}

    def gc(self, now: float) -> None:
        """Drop groups whose newest entry is older than the rule timespan."""
        with self._lock:
            for rule in self.rules:
                groups = self._state.get(rule.id, {})
                for k in [k for k, dq in groups.items() if not dq or dq[-1][0] < now - rule.timespan]:
                    groups.pop(k, None)
