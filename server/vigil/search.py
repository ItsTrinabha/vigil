"""VQL, Vigil's log search language, compiled to parameterised SQL.

    source.ip:203.0.113.5 AND event.action:ssh_login_failed
    user.name:adm* NOT host.name:web01
    http.response.status_code>=500 | stats count by source.ip
    "Failed password" | top user.name
    source.ip:10.0.0.0/8 | head 20

* `field:value` (case-insensitive, `*` and `?` wildcards, CIDR for IPs)
* `field!=value`, `field>N`, `field>=N`, `field<N`, `field<=N`, `field:*` (exists)
* bare words / "quoted phrases" search the raw message (FTS5 full-text index)
* AND (implicit), OR, NOT / leading `-`, parentheses
* pipes: `| stats count by f1, f2`, `| top f`, `| head N`, `| sort [-]f`, `| table f1, f2`

User input never reaches SQL text: field names are validated against a
strict pattern and every value is a bound parameter.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

COLUMN_MAP = {
    "host.name": "host", "host": "host", "user.name": "user_name", "user": "user_name",
    "source.ip": "src_ip", "src_ip": "src_ip", "event.action": "action", "action": "action",
    "event.outcome": "outcome", "outcome": "outcome", "log.category": "category", "category": "category",
    "source.geo.country_iso_code": "src_country", "country": "src_country", "log.product": "product",
    "message": "message", "agent.id": "agent_id", "log.source": "source",
}
_FIELD_RX = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@\-]{0,99}$")
_TOKEN = re.compile(r'''\s*(?:(?P<q>"(?:[^"\\]|\\.)*")|(?P<op>!=|>=|<=|[:=><()|,])|(?P<w>[^\s:=!<>()|,"]+))''')


class SearchError(ValueError):
    pass


@dataclass
class Compiled:
    where: str
    params: list
    commands: list[tuple[str, list[str]]] = field(default_factory=list)


def field_sql(name: str) -> str:
    if name in COLUMN_MAP:
        return COLUMN_MAP[name]
    if not _FIELD_RX.match(name):
        raise SearchError(f"invalid field name {name!r}")
    return f"json_extract(fields, '$.\"{name}\"')"


def _tokens(q: str) -> list[tuple[str, str]]:
    pos, out = 0, []
    while pos < len(q):
        if q[pos:].strip() == "":
            break
        m = _TOKEN.match(q, pos)
        if not m or m.end() == pos:
            raise SearchError(f"cannot parse near {q[pos:pos+20]!r}")
        pos = m.end()
        if m.group("q") is not None:
            out.append(("str", re.sub(r'\\(.)', r"\1", m.group("q")[1:-1])))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            out.append(("word", m.group("w")))
    return out


def _like(value: str) -> str:
    v = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return v.replace("*", "%").replace("?", "_")


def _fts_term(text: str) -> str:
    text = text.strip()
    if text.endswith("*") and "*" not in text[:-1]:
        return '"' + text[:-1].replace('"', '""') + '"*'
    return '"' + text.replace("*", " ").replace('"', '""') + '"'


class _Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0
        self.params: list = []

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self) -> Compiled:
        where = "1=1"
        if self.peek()[0] is not None and self.peek() != ("op", "|"):
            where = self.or_expr()
        cmds = []
        while self.peek() == ("op", "|"):
            self.take()
            cmds.append(self.command())
        if self.peek()[0] is not None:
            raise SearchError(f"unexpected {self.peek()[1]!r}")
        return Compiled(where, self.params, cmds)

    def command(self) -> tuple[str, list[str]]:
        kind, name = self.take()
        if kind != "word":
            raise SearchError("expected a command after |")
        name = name.lower()
        args: list[str] = []
        while self.peek()[0] is not None and self.peek() != ("op", "|"):
            k, v = self.take()
            if (k, v) == ("op", ","):
                continue
            args.append(v)
        if name == "stats":
            if not args or args[0].lower() != "count":
                raise SearchError("only `stats count [by f1, f2]` is supported")
            by = []
            if len(args) > 1:
                if args[1].lower() != "by":
                    raise SearchError("expected `by` after `stats count`")
                by = args[2:]
            for f in by:
                field_sql(f)
            return ("stats", by)
        if name == "top":
            if len(args) < 1:
                raise SearchError("`top` needs a field")
            for f in args:
                field_sql(f)
            return ("top", args)
        if name == "head":
            if len(args) != 1 or not args[0].isdigit():
                raise SearchError("`head` takes a number")
            return ("head", args)
        if name == "sort":
            if len(args) != 1:
                raise SearchError("`sort` takes one field")
            field_sql(args[0].lstrip("-+"))
            return ("sort", args)
        if name in ("table", "fields"):
            for f in args:
                if not _FIELD_RX.match(f):
                    raise SearchError(f"invalid field {f!r}")
            return ("table", args)
        raise SearchError(f"unknown command {name!r}")

    def or_expr(self) -> str:
        parts = [self.and_expr()]
        while self.peek()[0] == "word" and self.peek()[1].upper() == "OR":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def and_expr(self) -> str:
        parts = [self.not_expr()]
        while True:
            k, v = self.peek()
            if k is None or (k, v) in (("op", ")"), ("op", "|")) or (k == "word" and v.upper() == "OR"):
                break
            if k == "word" and v.upper() == "AND":
                self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def not_expr(self) -> str:
        k, v = self.peek()
        if k == "word" and v.upper() == "NOT":
            self.take()
            return f"NOT ({self.not_expr()})"
        if k == "word" and v.startswith("-") and len(v) > 1 and self.peek(1) in (("op", ":"), ("op", "=")):
            self.t[self.i] = ("word", v[1:])
            return f"NOT ({self.atom()})"
        return self.atom()

    def atom(self) -> str:
        k, v = self.take()
        if (k, v) == ("op", "("):
            inner = self.or_expr()
            if self.take() != ("op", ")"):
                raise SearchError("missing )")
            return inner
        if k is None:
            raise SearchError("unexpected end of query")
        nk, nv = self.peek()
        if k == "word" and nk == "op" and nv in (":", "=", "!=", ">", ">=", "<", "<="):
            self.take()
            vk, value = self.take()
            if vk not in ("word", "str"):
                raise SearchError(f"missing value for {v}")
            return self.comparison(v, nv, value, quoted=vk == "str")
        if k in ("word", "str"):
            self.params.append(_fts_term(v))
            return "id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
        raise SearchError(f"unexpected {v!r}")

    def comparison(self, fname: str, op: str, value: str, quoted: bool) -> str:
        col = field_sql(fname)
        if op in (">", ">=", "<", "<="):
            try:
                num = float(value)
            except ValueError:
                raise SearchError(f"{fname}{op} needs a number") from None
            self.params.append(num)
            return f"CAST({col} AS REAL) {op} ?"
        neg = op == "!="
        if value == "*" and not quoted:
            sql = f"({col} IS NOT NULL AND {col} != '')"
        elif "/" in value and not quoted and _is_cidr(value):
            self.params.append(value)
            sql = f"cidr_match({col}, ?)"
        elif ("*" in value or "?" in value) and not quoted:
            self.params.append(_like(value))
            sql = f"CAST({col} AS TEXT) LIKE ? ESCAPE '\\'"
        else:
            self.params.append(value)
            sql = f"CAST({col} AS TEXT) = ? COLLATE NOCASE"
        return f"NOT ({sql})" if neg else sql


def _is_cidr(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def cidr_match(ip, net) -> int:
    if ip is None:
        return 0
    try:
        return int(ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(net), strict=False))
    except ValueError:
        return 0


def compile_query(q: str) -> Compiled:
    q = (q or "").strip()
    if len(q) > 4000:
        raise SearchError("query too long")
    return _Parser(_tokens(q)).parse()


def run_search(conn, q: str, start: float, end: float, limit: int = 100, offset: int = 0,
               buckets: int = 60) -> dict:
    conn.create_function("cidr_match", 2, cidr_match, deterministic=True)
    c = compile_query(q)
    where = f"ts >= ? AND ts <= ? AND {c.where}"
    params = [start, end, *c.params]
    cmds = dict((k, v) for k, v in c.commands)
    limit = min(int(cmds["head"][0]) if "head" in cmds else limit, 1000)

    if "stats" in cmds or "top" in cmds:
        by = cmds.get("stats") if "stats" in cmds else cmds["top"]
        n = 10 if "top" in cmds and "head" not in cmds else limit
        if by:
            sel = ", ".join(f"{field_sql(f)} AS c{i}" for i, f in enumerate(by))
            grp = ", ".join(f"c{i}" for i in range(len(by)))
            sql = f"SELECT {sel}, COUNT(*) AS count FROM events WHERE {where} GROUP BY {grp} ORDER BY count DESC LIMIT ?"
            rows = conn.execute(sql, [*params, n]).fetchall()
            return {"type": "stats", "columns": [*by, "count"],
                    "rows": [[r[f"c{i}"] for i in range(len(by))] + [r["count"]] for r in rows]}
        total = conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
        return {"type": "stats", "columns": ["count"], "rows": [[total]]}

    order = "ts DESC"
    if "sort" in cmds:
        f = cmds["sort"][0]
        order = f"{field_sql(f.lstrip('-+'))} {'DESC' if f.startswith('-') else 'ASC'}, ts DESC"
    rows = conn.execute(f"SELECT id, ts, host, message, fields FROM events WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                        [*params, limit, offset]).fetchall()
    total = conn.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE {where} LIMIT 100000)", params).fetchone()[0]
    width = max(1.0, (end - start) / buckets)
    hist_rows = conn.execute(
        f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, COUNT(*) AS n FROM events WHERE {where} GROUP BY b",
        [start, width, *params]).fetchall()
    hist = [0] * buckets
    for r in hist_rows:
        if 0 <= r["b"] < buckets:
            hist[r["b"]] += r["n"]
    return {"type": "events", "total": total, "total_capped": total >= 100000,
            "events": [{"id": r["id"], "ts": r["ts"], "host": r["host"], "message": r["message"],
                        "fields": r["fields"]} for r in rows],
            "histogram": {"start": start, "width": width, "counts": hist},
            "columns": cmds.get("table")}
