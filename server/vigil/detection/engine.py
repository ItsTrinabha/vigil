"""Detection engine: loads Sigma + correlation rules and evaluates events.

Rules are bucketed by logsource so each event is only tested against the
rules that can apply to it, which keeps throughput high with thousands of
rules loaded.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .correlation import CorrelationEngine, CorrelationRule, Hit, compile_correlation
from .sigma import SigmaRule, compile_rule

try:
    _Loader = yaml.CSafeLoader
except AttributeError:  # pragma: no cover
    _Loader = yaml.SafeLoader

log = logging.getLogger("vigil.detection")


@dataclass
class Detection:
    rule_id: str
    rule_title: str
    rule_type: str            # sigma, correlation, ueba, threatintel, system
    severity: str
    event: dict
    event_ids: list[int]
    first_ts: float
    last_ts: float
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    group: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    description: str = ""


@dataclass
class LoadReport:
    files: int = 0
    rules: int = 0
    correlations: int = 0
    errors: list[dict] = field(default_factory=list)
    seconds: float = 0.0


class DetectionEngine:
    def __init__(self) -> None:
        self.rules: list[SigmaRule] = []
        self.correlations: list[CorrelationRule] = []
        self.corr_engine = CorrelationEngine([])
        self._buckets: dict[tuple, list[SigmaRule]] = {}
        self._silent: set[str] = set()
        self.report = LoadReport()
        self.stats: dict[str, int] = defaultdict(int)

    # ---------------------------------------------------------------- load
    def load_dirs(self, dirs: list[Path], disabled: set[str] | None = None) -> LoadReport:
        rules, corrs, rep = [], [], LoadReport()
        t0 = time.time()
        for d in dirs:
            for path in sorted(Path(d).rglob("*.yml")) + sorted(Path(d).rglob("*.yaml")):
                rep.files += 1
                try:
                    docs = list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=_Loader))
                except Exception as exc:
                    rep.errors.append({"path": str(path), "error": f"YAML: {exc}"[:300]})
                    continue
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    if "correlation" in doc:
                        c = compile_correlation(doc, str(path))
                        corrs.append(c)
                        if c.error:
                            rep.errors.append({"path": str(path), "id": c.id, "error": c.error})
                    elif "detection" in doc:
                        r = compile_rule(doc, str(path))
                        rules.append(r)
                        if r.error:
                            rep.errors.append({"path": str(path), "id": r.id, "error": r.error})
        self.set_rules(rules, corrs, disabled)
        rep.rules = sum(1 for r in rules if not r.error)
        rep.correlations = sum(1 for c in corrs if not c.error)
        rep.seconds = round(time.time() - t0, 2)
        self.report = rep
        log.info("loaded %d sigma rules, %d correlations from %d files (%d errors) in %.1fs",
                 rep.rules, rep.correlations, rep.files, len(rep.errors), rep.seconds)
        return rep

    def set_rules(self, rules: list[SigmaRule], corrs: list[CorrelationRule], disabled: set[str] | None = None) -> None:
        disabled = disabled or set()
        # de-duplicate by id, keeping the first one loaded (Vigil rules load before SigmaHQ)
        seen: set[str] = set()
        uniq = []
        for r in rules:
            if r.id in seen:
                continue
            seen.add(r.id)
            r.enabled = r.id not in disabled
            uniq.append(r)
        for c in corrs:
            c.enabled = c.id not in disabled
        self.rules = uniq
        self.correlations = corrs
        self.corr_engine = CorrelationEngine(corrs)
        buckets: dict[tuple, list[SigmaRule]] = defaultdict(list)
        for r in uniq:
            if r.predicate is None:
                continue
            ls = r.logsource
            buckets[(ls.get("product"), ls.get("category"), ls.get("service"))].append(r)
        self._buckets = dict(buckets)
        # Base Sigma rules referenced only by non-generating correlations do not alert on
        # their own. Correlation results always alert, including chained ones.
        refs = self.corr_engine.referenced()
        generating = {ref for c in self.corr_engine.rules if c.generate for ref in c.rules}
        self._silent = {ref for ref in refs if ref not in generating}

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        for r in list(self.rules) + list(self.correlations):
            if r.id == rule_id:
                r.enabled = enabled
                return True
        return False

    def all_rules(self) -> list[dict]:
        return [r.summary() for r in self.rules] + [c.summary() for c in self.correlations]

    def get_rule(self, rule_id: str):
        for r in list(self.rules) + list(self.correlations):
            if r.id == rule_id:
                return r
        return None

    # ------------------------------------------------------------- evaluate
    def _candidates(self, ev: dict):
        prod, cat, svcs = ev.get("log.product"), ev.get("log.category"), ev.get("log.services") or ()
        for (p, c, s), rules in self._buckets.items():
            if p and p != prod:
                continue
            if c and c != cat:
                continue
            if s and s not in svcs:
                continue
            yield from rules

    def evaluate(self, ev: dict, event_id: int | None) -> list[Detection]:
        out: list[Detection] = []
        ids = [event_id] if event_id is not None else []
        ts = float(ev.get("@timestamp") or time.time())
        for rule in self._candidates(ev):
            if not rule.enabled:
                continue
            try:
                hit = rule.predicate(ev)  # type: ignore[misc]
            except Exception:
                hit = False
            if not hit:
                continue
            self.stats[rule.id] += 1
            keys = tuple(k for k in (rule.name, rule.id) if k)
            if not any(k in self._silent for k in keys):
                out.append(Detection(rule.id, rule.title, "sigma", rule.level, ev, ids, ts, ts,
                                     rule.tactics, rule.techniques, description=rule.description,
                                     details={"rule_path": Path(rule.path).name}))
            for cm in self.corr_engine.process(Hit(keys, ts, ev, ids)):
                c = cm.rule
                self.stats[c.id] += 1
                out.append(Detection(c.id, c.title, "correlation", c.level, cm.event, cm.event_ids, cm.first_ts,
                                     cm.last_ts, c.tactics, c.techniques, cm.group,
                                     {**cm.details, "correlation_type": c.type, "timespan_s": c.timespan},
                                     c.description))
        return out
