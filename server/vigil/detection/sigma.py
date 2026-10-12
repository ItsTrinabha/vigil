"""A Sigma rule engine (https://sigmahq.io) that evaluates rules directly
against normalised events in memory, without converting them to a query
language first.

Supported:
  * detection maps / lists of maps / keyword lists, `null` values
  * wildcards `*` `?` with escaping, case-insensitive matching by default
  * modifiers: contains startswith endswith all re (i m s) cidr base64
    base64offset utf16le utf16be utf16 wide windash exists gt gte lt lte cased
    fieldref
  * conditions: and / or / not, parentheses, `1 of x*`, `all of x*`,
    `1 of them`, `all of them`
  * logsource matching on product / category / service
  * Sigma field taxonomy mapped onto the normalised event schema
Unsupported features (e.g. `expand` placeholders, legacy `| count()`
aggregations) are reported per rule instead of crashing the loader.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Predicate = Callable[[dict], bool]

LEVELS = ["informational", "low", "medium", "high", "critical"]


class SigmaError(Exception):
    pass


# --------------------------------------------------------------------------
# Field mapping: Sigma taxonomy name -> candidate normalised keys (OR).
# Direct lookup of the Sigma name is always tried first, so Windows EventData
# names and auditd keys match without an entry here.
# --------------------------------------------------------------------------
FIELD_MAP: dict[str, tuple[str, ...]] = {
    # webserver / proxy taxonomy
    "c-ip": ("source.ip",), "clientip": ("source.ip",),
    "cs-method": ("http.request.method",),
    "cs-uri-query": ("url.original", "url.decoded"),
    "cs-uri-stem": ("url.path",),
    "cs-uri": ("url.original", "url.decoded"),
    "c-uri": ("url.original", "url.decoded"),
    "c-uri-query": ("url.query",),
    "c-uri-stem": ("url.path",),
    "c-uri-extension": ("url.extension",),
    "sc-status": ("http.response.status_code",),
    "cs-user-agent": ("user_agent.original",), "c-useragent": ("user_agent.original",),
    "cs-referer": ("http.request.referrer",), "cs-referrer": ("http.request.referrer",),
    "cs-host": ("url.domain",), "r-dns": ("url.domain",), "cs-username": ("user.name",),
    "sc-bytes": ("http.response.body.bytes",),
    # generic
    "User": ("user.name",), "user": ("user.name",), "username": ("user.name",),
    "SourceIp": ("source.ip",), "src_ip": ("source.ip",), "SourcePort": ("source.port",),
    "DestinationIp": ("destination.ip",), "DestinationPort": ("destination.port",),
    "dst_ip": ("destination.ip",), "dst_port": ("destination.port",),
    "Hostname": ("host.name",), "ComputerName": ("host.name",),
    "Image": ("process.executable",), "CommandLine": ("process.command_line",),
    "ParentImage": ("process.parent.executable",), "ParentCommandLine": ("process.parent.command_line",),
    "CurrentDirectory": ("process.working_directory",), "ProcessId": ("process.pid",),
}


def _field_values(event: dict, name: str) -> list:
    if name in event:
        v = event[name]
        return v if isinstance(v, list) else [v]
    keys = FIELD_MAP.get(name)
    if keys:
        out = []
        for k in keys:
            if k in event:
                v = event[k]
                out.extend(v if isinstance(v, list) else [v])
        return out
    return []


def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


# --------------------------------------------------------------------------
# Value matchers
# --------------------------------------------------------------------------
def _wildcard_regex(pattern: str, mode: str) -> str:
    """Translate a Sigma wildcard string into a regex body. mode in eq/contains/startswith/endswith."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    if mode == "contains":
        return body
    if mode == "startswith":
        return "^" + body
    if mode == "endswith":
        return body + "$"
    return "^" + body + "$"


def _has_wildcards(s: str) -> bool:
    return bool(re.search(r"(?<!\\)[*?]", s))


def _unescape(s: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", s)


def _string_matcher(pattern: str, mode: str, cased: bool) -> Callable[[str], bool]:
    if not _has_wildcards(pattern):
        lit = _unescape(pattern)
        if not cased:
            lit = lit.lower()
        if mode == "contains":
            return (lambda s: lit in s) if cased else (lambda s: lit in s.lower())
        if mode == "startswith":
            return (lambda s: s.startswith(lit)) if cased else (lambda s: s.lower().startswith(lit))
        if mode == "endswith":
            return (lambda s: s.endswith(lit)) if cased else (lambda s: s.lower().endswith(lit))
        return (lambda s: s == lit) if cased else (lambda s: s.lower() == lit)
    rx = re.compile(_wildcard_regex(pattern, mode), re.S | (0 if cased else re.I))
    return lambda s: rx.search(s) is not None


def _windash_variants(s: str) -> list[str]:
    dashes = ["-", "/", "–", "—", "―"]
    out = {s}
    for d in dashes:
        out.add(re.sub(r"(^|\s)[-/]", lambda m, d=d: m.group(1) + d, s))
    return sorted(out)


def _b64_offsets(data: bytes) -> list[str]:
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + data).decode()
        start = (0, 2, 3)[i]
        end_trim = (0, -3, -2)[(len(data) + i) % 3]
        out.append(enc[start: len(enc) + end_trim if end_trim else None])
    return out


@dataclass
class FieldSpec:
    field: str | None  # None => keyword search across the raw message
    modifiers: list[str]
    values: list[Any]


def compile_field(spec: FieldSpec) -> Predicate:
    mods = list(spec.modifiers)
    name = spec.field
    cased = "cased" in mods
    match_all = "all" in mods
    values = spec.values

    if "exists" in mods:
        want = bool(values[0]) if values else True
        return lambda ev: (len([v for v in _field_values(ev, name) if v not in (None, "")]) > 0) == want

    if "fieldref" in mods:
        refs = [str(v) for v in values]

        def fieldref(ev):
            mine = [_to_str(v).lower() for v in _field_values(ev, name)]
            res = [any(_to_str(o).lower() in mine for o in _field_values(ev, r)) for r in refs]
            return all(res) if match_all else any(res)
        return fieldref

    # transform values (encodings)
    tvals: list[Any] = []
    for v in values:
        if isinstance(v, str):
            vs = [v]
            if "windash" in mods:
                vs = [x for s in vs for x in _windash_variants(s)]
            enc = None
            if "utf16le" in mods or "wide" in mods:
                enc = "utf-16-le"
            elif "utf16be" in mods:
                enc = "utf-16-be"
            elif "utf16" in mods:
                enc = "utf-16"
            if "base64" in mods or "base64offset" in mods:
                out = []
                for s in vs:
                    raw = s.encode(enc) if enc else s.encode()
                    out.extend(_b64_offsets(raw) if "base64offset" in mods else [base64.b64encode(raw).decode()])
                vs = out
            tvals.extend(vs)
        else:
            tvals.append(v)

    mode = "eq"
    for m in ("contains", "startswith", "endswith"):
        if m in mods:
            mode = m
    if "base64offset" in mods and mode == "eq":
        mode = "contains"

    matchers: list[Callable[[Any], bool]] = []
    for v in tvals:
        if v is None:
            matchers.append(None)  # type: ignore[arg-type]
        elif "re" in mods:
            flags = 0
            if "i" in mods:
                flags |= re.I
            if "m" in mods:
                flags |= re.M
            if "s" in mods:
                flags |= re.S
            rx = re.compile(str(v), flags)
            matchers.append(lambda x, rx=rx: rx.search(_to_str(x)) is not None)
        elif "cidr" in mods:
            net = ipaddress.ip_network(str(v), strict=False)

            def cidr(x, net=net):
                try:
                    return ipaddress.ip_address(_to_str(x)) in net
                except ValueError:
                    return False
            matchers.append(cidr)
        elif any(m in mods for m in ("gt", "gte", "lt", "lte")):
            op = next(m for m in ("gt", "gte", "lt", "lte") if m in mods)
            num = float(v)

            def cmp(x, num=num, op=op):
                try:
                    f = float(x)
                except (TypeError, ValueError):
                    return False
                return {"gt": f > num, "gte": f >= num, "lt": f < num, "lte": f <= num}[op]
            matchers.append(cmp)
        elif isinstance(v, bool):
            matchers.append(lambda x, v=v: _to_str(x).lower() == _to_str(v))
        elif isinstance(v, (int, float)) and mode == "eq":
            sv = _to_str(v)
            matchers.append(lambda x, sv=sv: _to_str(x) == sv)
        else:
            sm = _string_matcher(_to_str(v), mode, cased)
            matchers.append(lambda x, sm=sm: sm(_to_str(x)))

    if name is None:  # keywords: full-text over the raw message
        kw = [_string_matcher(_to_str(v), "contains", cased) for v in tvals if v is not None]

        def keyword(ev):
            msg = ev.get("message") or ""
            res = (m(msg) for m in kw)
            return all(res) if match_all else any(res)
        return keyword

    def pred(ev):
        vals = _field_values(ev, name)
        present = [x for x in vals if x is not None and x != ""]

        def one(m):
            if m is None:
                return not present
            return any(m(x) for x in present)
        if match_all:
            return all(one(m) for m in matchers)
        return any(one(m) for m in matchers)
    return pred


def _parse_key(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [p.lower() for p in parts[1:] if p]


SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "base64",
                  "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash", "exists", "gt", "gte",
                  "lt", "lte", "cased", "fieldref"}


def compile_selection(sel: Any) -> Predicate:
    if isinstance(sel, dict):
        preds = []
        for key, val in sel.items():
            name, mods = _parse_key(str(key))
            bad = [m for m in mods if m not in SUPPORTED_MODS]
            if bad:
                raise SigmaError(f"unsupported modifier(s): {', '.join(bad)}")
            values = val if isinstance(val, list) else [val]
            preds.append(compile_field(FieldSpec(name or None, mods, values)))
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            preds = [compile_selection(x) for x in sel]
            return lambda ev: any(p(ev) for p in preds)
        if all(not isinstance(x, (dict, list)) for x in sel):
            return compile_field(FieldSpec(None, [], sel))
        raise SigmaError("mixed list in selection")
    if isinstance(sel, (str, int, float)):
        return compile_field(FieldSpec(None, [], [sel]))
    raise SigmaError(f"unsupported selection type {type(sel).__name__}")


# --------------------------------------------------------------------------
# Condition parser (recursive descent)
# --------------------------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+|\|)")


def _tokenize(cond: str) -> list[str]:
    pos, out = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"bad condition near {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _CondParser:
    def __init__(self, tokens: list[str], sels: dict[str, Predicate]):
        self.t = tokens
        self.i = 0
        self.sels = sels

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self) -> Predicate:
        p = self.expr()
        if self.peek() is not None:
            if self.peek() == "|":
                raise SigmaError("legacy aggregation conditions (| count() ...) are not supported; use correlation rules")
            raise SigmaError(f"unexpected token {self.peek()!r}")
        return p

    def expr(self) -> Predicate:
        left = self.term()
        while self.peek() and self.peek().lower() == "or":
            self.take()
            right = self.term()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def term(self) -> Predicate:
        left = self.factor()
        while self.peek() and self.peek().lower() == "and":
            self.take()
            right = self.factor()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def factor(self) -> Predicate:
        tok = self.take()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        low = tok.lower()
        if low == "not":
            inner = self.factor()
            return lambda ev: not inner(ev)
        if tok == "(":
            p = self.expr()
            if self.take() != ")":
                raise SigmaError("missing )")
            return p
        if (low in ("all", "any") or low.isdigit()) and self.peek() and self.peek().lower() == "of":
            self.take()
            target = self.take()
            if target is None:
                raise SigmaError("missing target after 'of'")
            if target.lower() == "them":
                names = [n for n in self.sels if not n.startswith("_")]
            else:
                rx = re.compile("^" + re.escape(target).replace(r"\*", ".*") + "$")
                names = [n for n in self.sels if rx.match(n)]
            if not names:
                raise SigmaError(f"no selection matches {target!r}")
            preds = [self.sels[n] for n in names]
            if low == "all":
                return lambda ev: all(p(ev) for p in preds)
            n_req = 1 if low == "any" else int(low)
            return lambda ev: sum(1 for p in preds if p(ev)) >= n_req
        if tok in self.sels:
            return self.sels[tok]
        raise SigmaError(f"unknown selection {tok!r}")


def compile_condition(cond: str, sels: dict[str, Predicate]) -> Predicate:
    return _CondParser(_tokenize(cond), sels).parse()


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: list[str]
    logsource: dict
    path: str
    author: str = ""
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    name: str | None = None
    raw: dict = field(default_factory=dict)
    predicate: Predicate | None = None
    error: str | None = None
    enabled: bool = True

    @property
    def techniques(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t, re.I)
            if m:
                out.append(m.group(1).upper())
        return out

    @property
    def tactics(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.match(r"^attack\.([a-z][a-z_-]+)$", t, re.I)
            if m and not re.match(r"^[gs]\d{4}$", m.group(1), re.I):
                out.append(m.group(1).replace("_", "-").lower())
        return out

    def matches_logsource(self, ev: dict) -> bool:
        ls = self.logsource
        p = ls.get("product")
        if p and p != ev.get("log.product"):
            return False
        c = ls.get("category")
        if c and c != ev.get("log.category"):
            return False
        s = ls.get("service")
        return not (s and s not in (ev.get("log.services") or ()))

    def match(self, ev: dict) -> bool:
        if self.predicate is None or not self.enabled:
            return False
        if not self.matches_logsource(ev):
            return False
        try:
            return self.predicate(ev)
        except Exception:
            return False

    def summary(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "status": self.status,
                "description": self.description, "tags": self.tags, "techniques": self.techniques,
                "tactics": self.tactics, "logsource": self.logsource, "path": self.path, "author": self.author,
                "references": self.references, "falsepositives": self.falsepositives, "error": self.error,
                "enabled": self.enabled, "name": self.name, "type": "sigma"}


def compile_rule(doc: dict, path: str = "") -> SigmaRule:
    level = str(doc.get("level") or "medium").lower()
    if level not in LEVELS:
        level = "medium"
    rule = SigmaRule(
        id=str(doc.get("id") or doc.get("name") or doc.get("title")), title=str(doc.get("title") or "untitled"),
        level=level, status=str(doc.get("status") or "experimental"), description=str(doc.get("description") or "").strip(),
        tags=[str(t) for t in doc.get("tags") or []], logsource=dict(doc.get("logsource") or {}), path=path,
        author=str(doc.get("author") or ""), references=list(doc.get("references") or []),
        falsepositives=[str(x) for x in doc.get("falsepositives") or []], name=doc.get("name"), raw=doc)
    try:
        det = doc.get("detection")
        if not isinstance(det, dict):
            raise SigmaError("missing detection")
        cond = det.get("condition")
        if isinstance(cond, list):
            if len(cond) != 1:
                cond = " or ".join(f"({c})" for c in cond)
            else:
                cond = cond[0]
        if not cond:
            raise SigmaError("missing condition")
        sels = {k: compile_selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
        rule.predicate = compile_condition(str(cond), sels)
    except SigmaError as exc:
        rule.error = str(exc)
    except (re.error, ValueError) as exc:
        rule.error = f"invalid value: {exc}"
    return rule
