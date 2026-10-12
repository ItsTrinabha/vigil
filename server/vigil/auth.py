"""Authentication for analysts (sessions) and agents (bearer tokens).

* Passwords: scrypt (N=2^15, r=8, p=1) with a per-user salt.
* Sessions: random 256-bit token in an HttpOnly, SameSite=Strict cookie; only
  a SHA-256 of the token is stored server side.
* CSRF: state-changing requests must carry `X-Vigil-Request: 1`, a header a
  cross-site form cannot set.
* Login throttling per username and per client IP.
* Agents: enrolled with a shared enrollment token, then each agent gets its
  own token (stored hashed) that can be revoked individually.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from .db import Database

ROLES = ("admin", "analyst", "viewer")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt$32768$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        test = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=len(dk) // 2)
        return hmac.compare_digest(test.hex(), dk)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


_DUMMY_HASH = hash_password(secrets.token_hex(8))


class LoginThrottle:
    """At most `limit` failures per key in `window` seconds."""

    def __init__(self, limit: int = 5, window: int = 300):
        self.limit, self.window = limit, window
        self.failures: dict[str, deque] = defaultdict(deque)

    def blocked(self, *keys: str) -> bool:
        now = time.time()
        for k in keys:
            dq = self.failures[k]
            while dq and dq[0] < now - self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                return True
        return False

    def fail(self, *keys: str) -> None:
        for k in keys:
            self.failures[k].append(time.time())

    def reset(self, *keys: str) -> None:
        for k in keys:
            self.failures.pop(k, None)


class Auth:
    def __init__(self, db: Database, session_hours: int = 12):
        self.db = db
        self.session_s = session_hours * 3600
        self.throttle = LoginThrottle()

    # ------------------------------------------------------------- users
    def ensure_admin(self, username: str, password: str | None) -> str | None:
        """Create the first admin. Returns the generated password if one was made."""
        if self.db.query_one("SELECT 1 FROM users LIMIT 1"):
            return None
        generated = None
        if not password:
            generated = password = secrets.token_urlsafe(12)
        self.create_user(username, password, "admin")
        return generated

    def create_user(self, username: str, password: str, role: str = "analyst") -> dict:
        if role not in ROLES:
            raise ValueError("invalid role")
        if not username or len(username) > 64 or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("username must be 1-64 letters, digits, '.', '-' or '_'")
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        self.db.execute("INSERT INTO users(username, password_hash, role, created_ts) VALUES(?,?,?,?)",
                        (username, hash_password(password), role, time.time()))
        return {"username": username, "role": role}

    def set_password(self, username: str, password: str) -> None:
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        self.db.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(password), username))
        self.db.execute("DELETE FROM sessions WHERE username=?", (username,))

    def authenticate(self, username: str, password: str, client_ip: str) -> tuple[str | None, str]:
        """Returns (session_token | None, reason)."""
        if self.throttle.blocked(f"u:{username}", f"ip:{client_ip}"):
            return None, "throttled"
        row = self.db.query_one("SELECT * FROM users WHERE username=? AND disabled=0", (username,))
        ok = verify_password(password, row["password_hash"] if row else _DUMMY_HASH)  # constant-ish time
        if not row or not ok:
            self.throttle.fail(f"u:{username}", f"ip:{client_ip}")
            return None, "invalid"
        self.throttle.reset(f"u:{username}")
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.db.execute("INSERT INTO sessions(token_hash, username, created_ts, expires_ts) VALUES(?,?,?,?)",
                        (token_hash(token), username, now, now + self.session_s))
        self.db.execute("DELETE FROM sessions WHERE expires_ts < ?", (now,))
        return token, "ok"

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        row = self.db.query_one(
            "SELECT u.username, u.role FROM sessions s JOIN users u ON u.username = s.username "
            "WHERE s.token_hash=? AND s.expires_ts > ? AND u.disabled=0", (token_hash(token), time.time()))
        return row

    def logout(self, token: str | None) -> None:
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))

    # ------------------------------------------------------------ agents
    def enroll_agent(self, enrollment_token: str, expected: str, hostname: str, os_name: str, version: str,
                     ip: str) -> dict | None:
        if not hmac.compare_digest(enrollment_token.encode(), expected.encode()):
            return None
        agent_id = "agt_" + secrets.token_hex(8)
        token = secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO agents(id, token_hash, hostname, os, version, ip, enrolled_ts, last_seen) VALUES(?,?,?,?,?,?,?,?)",
            (agent_id, token_hash(token), hostname[:255], os_name[:255], version[:32], ip, time.time(), time.time()))
        return {"agent_id": agent_id, "token": token}

    def agent_for_token(self, token: str | None) -> dict | None:
        if not token:
            return None
        return self.db.query_one("SELECT * FROM agents WHERE token_hash=? AND status='active'", (token_hash(token),))
