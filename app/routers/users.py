"""Console accounts and the activity trail.

Two guardrails matter more than the CRUD here:
  * the last active admin can never be removed, demoted or disabled, because
    that would lock everyone out of a box that lives on an isolated network;
  * nobody can raise their own role, so a compromised responder session cannot
    escalate itself.
"""
from __future__ import annotations

import re
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import (
    hash_password,
    password_problem,
    require_admin,
    require_console,
    verify_password,
)
from ..database import get_db
from ..models import AuditEvent, Role, User, utcnow

router = APIRouter()

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "full_name": u.full_name or "",
        "role": u.role.value if hasattr(u.role, "value") else str(u.role),
        "active": bool(u.active),
        "must_change_password": bool(u.must_change_password),
        "locked": u.is_locked(),
        "created_at": _iso(u.created_at),
        "created_by": u.created_by,
        "last_login": _iso(u.last_login),
    }


def _active_admins(db: Session, excluding: str | None = None) -> int:
    q = db.query(User).filter(User.role == Role.ADMIN, User.active == True)  # noqa: E712
    if excluding:
        q = q.filter(User.id != excluding)
    return q.count()


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


@router.get("")
def list_users(db: Session = Depends(get_db), _a: User = Depends(require_admin)):
    users = db.query(User).order_by(User.role, User.username).all()
    return {"users": [user_dict(u) for u in users]}


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class CreateUser(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: str = ""
    full_name: str = ""
    password: str
    role: Role = Role.VIEWER
    must_change_password: bool = True


@router.post("")
def create_user(
    payload: CreateUser,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    username = payload.username.strip().lower()
    # Email is optional: plenty of estates identify people by username alone,
    # and refusing to create the account over a missing address helps nobody.
    email = (payload.email or "").strip().lower()

    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Usernames use 3–32 lowercase letters, digits, dot, dash or underscore.",
        )
    if email and not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="That email address doesn't look valid.")

    problem = password_problem(payload.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail=f"The username {username} is taken.")
    if email and db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="That email already has an account.")

    user = User(
        username=username,
        email=email or None,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        must_change_password=payload.must_change_password,
        created_by=admin.username,
    )
    db.add(user)
    db.add(AuditEvent(kind="user.created", subject=username,
                      detail=f"role={payload.role.value} by {admin.username}"))
    db.commit()
    db.refresh(user)
    return user_dict(user)


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


class UpdateUser(BaseModel):
    email: str | None = None
    full_name: str | None = None
    role: Role | None = None
    active: bool | None = None


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: UpdateUser,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="No such account.")

    changes = []

    if payload.email is not None:
        email = payload.email.strip().lower()
        if not EMAIL_RE.match(email):
            raise HTTPException(status_code=400, detail="That email address doesn't look valid.")
        clash = db.query(User).filter(User.email == email, User.id != user_id).first()
        if clash:
            raise HTTPException(status_code=409, detail="That email already has an account.")
        if email != user.email:
            changes.append("email")
            user.email = email

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()

    if payload.role is not None and payload.role != user.role:
        if user.id == admin.id:
            raise HTTPException(
                status_code=400,
                detail="You can't change your own role. Ask another admin.",
            )
        if user.role == Role.ADMIN and _active_admins(db, excluding=user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail="This is the last admin. Promote someone else first.",
            )
        changes.append(f"role {user.role.value}->{payload.role.value}")
        user.role = payload.role

    if payload.active is not None and bool(payload.active) != bool(user.active):
        if user.id == admin.id:
            raise HTTPException(status_code=400, detail="You can't disable your own account.")
        if not payload.active and user.role == Role.ADMIN and _active_admins(db, excluding=user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail="This is the last admin. Promote someone else first.",
            )
        changes.append("enabled" if payload.active else "disabled")
        user.active = bool(payload.active)
        if payload.active:
            # Re-enabling should also clear a lockout, or the person still can't get in.
            user.failed_logins = 0
            user.locked_until = None

    if changes:
        db.add(AuditEvent(kind="user.updated", subject=user.username,
                          detail=f"{', '.join(changes)} by {admin.username}"))
    db.commit()
    db.refresh(user)
    return user_dict(user)


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


# NOTE: /me/password must be declared before /{user_id}/password. FastAPI
# matches routes in registration order, so the parameterised path would
# otherwise swallow "me" as a user id and bounce the caller off the admin guard.

class ChangeOwnPassword(BaseModel):
    current_password: str
    new_password: str


@router.post("/me/password")
def change_own_password(
    payload: ChangeOwnPassword,
    db: Session = Depends(get_db),
    user: User = Depends(require_console),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Your current password is wrong.")

    problem = password_problem(payload.new_password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Pick a password you haven't used here.")

    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    db.add(AuditEvent(kind="user.password_changed", subject=user.username))
    db.commit()
    return {"ok": True}


class ResetPassword(BaseModel):
    password: str
    must_change_password: bool = True


@router.post("/{user_id}/password")
def reset_password(
    user_id: str,
    payload: ResetPassword,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="No such account.")

    problem = password_problem(payload.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    user.password_hash = hash_password(payload.password)
    user.must_change_password = payload.must_change_password
    user.failed_logins = 0
    user.locked_until = None
    db.add(AuditEvent(kind="user.password_reset", subject=user.username,
                      detail=f"by {admin.username}"))
    db.commit()
    return {"ok": True, "username": user.username}


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="No such account.")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You can't delete your own account.")
    if user.role == Role.ADMIN and _active_admins(db, excluding=user.id) == 0:
        raise HTTPException(
            status_code=400,
            detail="This is the last admin. Promote someone else first.",
        )

    username = user.username
    db.delete(user)
    db.add(AuditEvent(kind="user.deleted", subject=username, detail=f"by {admin.username}"))
    db.commit()
    return {"deleted": username}


# ---------------------------------------------------------------------------
# Activity trail
# ---------------------------------------------------------------------------


@router.get("/activity/log")
def activity(
    limit: int = 200,
    db: Session = Depends(get_db),
    _a: User = Depends(require_admin),
):
    """Who did what. Useful during an incident review of the response itself."""
    rows = (
        db.query(AuditEvent)
        .order_by(AuditEvent.at.desc())
        .limit(min(limit, 1000))
        .all()
    )
    return {
        "events": [
            {"at": _iso(e.at), "kind": e.kind, "subject": e.subject, "detail": e.detail}
            for e in rows
        ]
    }
