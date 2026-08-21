"""Two separate identities live here.

* Console operators sign in with a password and carry a signed session cookie.
* Agents present the ``X-Agent-Key`` they were handed at enrollment.

Keeping them apart means a stolen agent key can never drive the console UI,
and a console session can never impersonate a host uploading results.

The session cookie carries only a user id. Every request re-reads that user
from the database, so deactivating an account or demoting a role takes effect
on the next click rather than whenever the cookie happens to expire.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import Agent, Role, User, utcnow

SESSION_COOKIE = "douglas_session"

# Password storage: scrypt from the standard library. Memory-hard, so a leaked
# database is expensive to attack with GPUs, and it costs us no dependency.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1

# One number, used everywhere a password is set: first-run change, the account
# form, and the recovery CLI. Having the shipped default be shorter than the
# floor the tool then demands is confusing, and confusion at the login screen
# is where people give up on a tool.
MIN_PASSWORD_LENGTH = 8
MAX_FAILED_LOGINS = 8
LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, want = stored.split("$")
        if scheme != "scrypt":
            return False
        got = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p),
        )
        return hmac.compare_digest(got.hex(), want)
    except (ValueError, TypeError):
        return False


def password_problem(password: str) -> str | None:
    """Return a plain-language reason the password is unusable, or None."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if password.lower() in {"douglas042", "password123", "changeme1234", "administrator"}:
        return "That password is too easy to guess. Pick something else."
    if password.strip() != password:
        return "Remove the leading or trailing spaces."
    return None


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def _sign(payload: bytes) -> str:
    sig = hmac.new(settings.session_secret.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_session(user_id: str) -> str:
    body = json.dumps(
        {"uid": user_id, "exp": int(time.time()) + settings.session_hours * 3600}
    ).encode()
    return f"{_b64(body)}.{_sign(body)}"


def read_session(token: str | None) -> str | None:
    """Return the user id carried by a valid, unexpired cookie."""
    if not token or "." not in token:
        return None
    raw, sig = token.rsplit(".", 1)
    try:
        body = _unb64(raw)
    except Exception:
        return None
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data.get("uid")


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------


def authenticate(db: Session, identifier: str, password: str) -> tuple[User | None, str]:
    """Check credentials. Returns (user, reason); reason is set only on failure.

    The reason stays vague on purpose so it never reveals whether an account
    exists. Lockout is the one exception, because someone locked out needs to
    know to stop retrying.
    """
    ident = (identifier or "").strip().lower()
    user = (
        db.query(User)
        .filter((User.username == ident) | (User.email == ident))
        .first()
    )

    if user is None:
        # Spend comparable time so response timing doesn't leak existence.
        hash_password(password or "x")
        return None, "That username and password don't match."

    if user.is_locked():
        return None, (
            f"Too many failed attempts. Wait {LOCKOUT_MINUTES} minutes "
            "or ask an admin to reset the password."
        )

    if not user.active:
        return None, "That account is disabled. Ask an admin to re-enable it."

    if not verify_password(password, user.password_hash):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_logins = 0
        db.commit()
        return None, "That username and password don't match."

    user.failed_logins = 0
    user.locked_until = None
    user.last_login = utcnow()
    db.commit()
    return user, ""


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def _user_from_token(raw: str, db: Session) -> User | None:
    """Resolve a bearer token into a stand-in user carrying its role.

    The token is not an account: it has a role but no password, cannot sign in
    and cannot be used to change accounts. That keeps automation from becoming
    a second, quieter way to administer the console.
    """
    from .models import ApiToken, utcnow
    from .services.integrations import token_fingerprint

    row = (
        db.query(ApiToken)
        .filter(ApiToken.fingerprint == token_fingerprint(raw))
        .first()
    )
    if row is None or not row.enabled:
        return None
    if row.expires_at:
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            return None

    row.last_used_at = utcnow()
    row.use_count = (row.use_count or 0) + 1
    db.commit()

    holder = User(
        id=f"token:{row.id}",
        username=f"token:{row.name}",
        full_name=f"API token: {row.name}",
        role=row.role,
        active=True,
    )
    return holder


def require_console(
    douglas_session: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    # A bearer token is checked first so a browser session left open in
    # another tab cannot silently grant a script more than its token allows.
    if authorization and authorization.lower().startswith("bearer "):
        holder = _user_from_token(authorization.split(" ", 1)[1].strip(), db)
        if holder is not None:
            return holder
        raise HTTPException(status_code=401, detail="That API token is not valid.")

    uid = read_session(douglas_session)
    if not uid:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    user = db.get(User, uid)
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return user


def require_role(minimum: Role):
    """Dependency factory guarding an endpoint behind a minimum role."""
    message = {
        Role.RESPONDER: "This needs responder access. Ask an admin to change your role.",
        Role.ADMIN: "This needs admin access.",
    }.get(minimum, "You don't have access to this.")

    def _guard(user: User = Depends(require_console)) -> User:
        if not user.can(minimum):
            raise HTTPException(status_code=403, detail=message)
        return user

    return _guard


require_responder = require_role(Role.RESPONDER)
require_admin = require_role(Role.ADMIN)


def require_agent(
    x_agent_id: str = Header(...),
    x_agent_key: str = Header(...),
    db: Session = Depends(get_db),
) -> Agent:
    agent = db.get(Agent, x_agent_id)
    if not agent or not secrets.compare_digest(agent.agent_key, x_agent_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent credentials rejected. Re-enroll this host.",
        )
    return agent
