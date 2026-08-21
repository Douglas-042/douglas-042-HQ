"""Command-line recovery for the console.

Console accounts live in the database, not in the environment, so changing
DOUGLAS_CONSOLE_PASSWORD after the first boot does nothing. That is deliberate,
but it means a forgotten admin password would otherwise lock you out of a box
sitting on an isolated network. This is the way back in.

    docker compose exec console python -m app.manage list
    docker compose exec console python -m app.manage passwd admin
    docker compose exec console python -m app.manage unlock admin
    docker compose exec console python -m app.manage promote a.yilmaz admin
    docker compose exec console python -m app.manage create ir.lead ir@corp.local admin
    docker compose exec console python -m app.manage reset
    docker compose exec console python -m app.manage version

Running without Docker: python -m app.manage list
"""
from __future__ import annotations

from pathlib import Path

import getpass
import secrets
import sys

from .auth import hash_password, password_problem
from .database import SessionLocal, init_db
from .models import AuditEvent, Role, User


def _die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _find(db, identifier: str) -> User:
    ident = identifier.strip().lower()
    user = db.query(User).filter(
        (User.username == ident) | (User.email == ident)
    ).first()
    if not user:
        _die(f"no account matches {identifier!r}. Run 'list' to see what exists.")
    return user


def _ask_password() -> str:
    """Read a password twice from the terminal, or generate one if piped."""
    if not sys.stdin.isatty():
        generated = "-".join(
            secrets.choice(
                ["harbor", "cinder", "lantern", "quartz", "meadow", "falcon",
                 "timber", "zenith", "garnet", "willow", "cobalt", "thistle"]
            )
            for _ in range(3)
        ) + f"-{secrets.randbelow(90) + 10}"
        print(f"No terminal available, generated a password: {generated}")
        return generated

    while True:
        first = getpass.getpass("New password: ")
        problem = password_problem(first)
        if problem:
            print(f"  {problem}")
            continue
        if first != getpass.getpass("Repeat it: "):
            print("  The two entries differ. Try again.")
            continue
        return first


def cmd_list(db, _args) -> None:
    # Print the database being read. Recovery goes wrong most often because
    # the tool is pointed at a different file than the running console — a
    # bind mount versus a named volume, or a stray DOUGLAS_DATA_DIR.
    from .config import settings

    print(f"database: {settings.database_url}")
    print(f"data dir: {settings.data_dir}\n")

    users = db.query(User).order_by(User.role, User.username).all()
    if not users:
        print("No accounts exist in this database.")
        print("Either the console has never started against it, or you are")
        print("pointed at the wrong path. Check the data dir above.\n")
        print("To create an admin here: python -m app.manage create <user> <email> admin")
        return
    print(f"{'USERNAME':<20} {'ROLE':<11} {'STATE':<12} {'EMAIL':<32} LAST SIGN-IN")
    for u in users:
        state = "disabled" if not u.active else "locked" if u.is_locked() else "active"
        if u.must_change_password and state == "active":
            state = "must change"
        last = u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "never"
        print(f"{u.username:<20} {u.role.value:<11} {state:<12} {u.email:<32} {last}")


def cmd_passwd(db, args) -> None:
    if not args:
        _die("usage: passwd <username>")
    user = _find(db, args[0])
    password = args[1] if len(args) > 1 else _ask_password()

    problem = password_problem(password)
    if problem:
        _die(problem)

    user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    user.active = True
    # Set from a shell by someone holding the server; make them replace it.
    user.must_change_password = True
    db.add(AuditEvent(kind="user.password_reset", subject=user.username,
                      detail="via command line"))
    db.commit()
    print(f"Password set for {user.username}. Any lockout is cleared and the")
    print("account is enabled. They will be asked to change it at next sign-in.")


def cmd_unlock(db, args) -> None:
    if not args:
        _die("usage: unlock <username>")
    user = _find(db, args[0])
    user.failed_logins = 0
    user.locked_until = None
    user.active = True
    db.add(AuditEvent(kind="user.updated", subject=user.username,
                      detail="unlocked via command line"))
    db.commit()
    print(f"{user.username} is unlocked and enabled. The password is unchanged.")


def cmd_promote(db, args) -> None:
    if len(args) < 2:
        _die("usage: promote <username> <admin|responder|viewer>")
    user = _find(db, args[0])
    try:
        role = Role(args[1].strip().lower())
    except ValueError:
        _die("role must be one of: admin, responder, viewer")
    was = user.role.value
    user.role = role
    db.add(AuditEvent(kind="user.updated", subject=user.username,
                      detail=f"role {was}->{role.value} via command line"))
    db.commit()
    print(f"{user.username}: {was} -> {role.value}")


def cmd_create(db, args) -> None:
    if len(args) < 2:
        _die("usage: create <username> <email> [role]")
    username, email = args[0].strip().lower(), args[1].strip().lower()
    role_name = args[2] if len(args) > 2 else "admin"
    try:
        role = Role(role_name.strip().lower())
    except ValueError:
        _die("role must be one of: admin, responder, viewer")

    if db.query(User).filter(User.username == username).first():
        _die(f"the username {username} is taken")
    if db.query(User).filter(User.email == email).first():
        _die("that email already has an account")

    password = args[3] if len(args) > 3 else _ask_password()
    problem = password_problem(password)
    if problem:
        _die(problem)

    user = User(
        username=username, email=email, full_name="",
        password_hash=hash_password(password), role=role,
        must_change_password=True, created_by="command line",
    )
    db.add(user)
    db.add(AuditEvent(kind="user.created", subject=username,
                      detail=f"role={role.value} via command line"))
    db.commit()
    print(f"Created {username} as {role.value}.")


def cmd_reset(db, _args) -> None:
    """Delete every console account so the next start rebuilds from .env.

    The way back when the database predates the current .env: accounts are read
    from the environment only when there are none, so this is what makes an
    edited .env take effect. Hosts, hunts and findings are untouched.
    """
    from .models import User

    users = db.query(User).all()
    if not users:
        print("No console accounts exist; the next start will create one from .env.")
        return

    print(f"This deletes {len(users)} console account(s):")
    for u in users:
        print(f"  {u.username}  ({u.email or 'no email'})")
    print("\nAgents, hunts and findings are not touched.")
    answer = input("Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        print("Cancelled.")
        return

    for u in users:
        db.delete(u)
    db.commit()
    print("\nAccounts removed. Restart the console and sign in with the")
    print("username and password from .env.")


def cmd_version(_db, _args) -> None:
    """Show what is actually running, and from where.

    Extracting an update into the wrong directory leaves the old console
    running with none of the new screens, and nothing on the page says so.
    This answers "did my update land" without guessing.
    """
    import re

    from .config import settings

    static = Settings_static()
    index = static / "index.html"

    print(f"code    : {Path(__file__).resolve().parent.parent}")
    print(f"static  : {static}")
    print(f"data    : {settings.data_dir}")
    print(f"build   : {settings.build_stamp}")
    print()

    if not index.exists():
        print("index.html is missing. This directory is not a complete install.")
        return

    views = re.findall(r'data-view="([^"]+)"', index.read_text(encoding="utf-8"))
    print(f"console screens: {len(views)}")
    print("  " + ", ".join(views))
    print()

    expected = {
        "dashboard", "cases", "fleet", "hunts", "findings", "triage", "stack",
        "graph", "matrix", "diff", "timeline", "rules", "myrules", "yara",
        "sigma", "feeds", "integrations", "users", "schedules", "deploy",
    }
    missing = sorted(expected - set(views))
    if missing:
        print("MISSING SCREENS: " + ", ".join(missing))
        print()
        print("This install predates the current release. The most common cause is")
        print("extracting the archive inside the folder instead of beside it, which")
        print("leaves a nested douglas-platform/douglas-platform and runs the old copy.")
        print("Check for one, then extract in the parent directory.")
    else:
        print("All expected screens are present.")
        print("If the browser still shows fewer, reload with Ctrl+Shift+R.")

    agent_dir = Path(settings.agent_dir)
    print()
    print("agents bundled:")
    for name in ("Douglas-042.ps1", "douglas-agent.ps1",
                 "douglas-042.sh", "douglas-agent.sh"):
        path = agent_dir / name
        state = f"{path.stat().st_size // 1024} KB" if path.exists() else "MISSING"
        print(f"  {name:22} {state}")


def Settings_static():
    from .config import settings

    return Path(settings.static_dir)


COMMANDS = {
    "list": cmd_list,
    "passwd": cmd_passwd,
    "unlock": cmd_unlock,
    "promote": cmd_promote,
    "create": cmd_create,
    "reset": cmd_reset,
    "version": cmd_version,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("commands: " + ", ".join(COMMANDS))
        return

    command = sys.argv[1]
    if command not in COMMANDS:
        _die(f"unknown command {command!r}. One of: {', '.join(COMMANDS)}")

    init_db()
    db = SessionLocal()
    try:
        COMMANDS[command](db, sys.argv[2:])
    finally:
        db.close()


if __name__ == "__main__":
    main()
