"""The incident-response actions an operator can run against a host.

A hunt tells you something is wrong. This is the part where you do something
about it, and doing it from the console matters: at 3am, on a host you may not
have credentials for, the alternative is an RDP session and a scrollback nobody
keeps.

The set is deliberately small. Every action here is one somebody actually
reaches for in the first ten minutes of an incident — look at what is running,
see who it is talking to, stop the thing, cut the host off, take a copy before
it changes. A larger catalogue of rarely-used commands would mostly serve to
make the dangerous ones harder to find.

Two properties are enforced rather than documented:

    Read-only actions and mutating ones are marked, and the console shows them
    differently. Listing processes and killing one are not the same kind of
    decision and must not look alike.

    Anything that changes the host requires a written reason. A containment
    action with no rationale is indistinguishable from a mistake once the
    person who ran it has gone home.

Isolation deserves its own note. It leaves the console reachable on purpose: a
host cut off from everything including its agent cannot be released remotely,
and someone would have to walk to it. That is a worse outcome than the small
risk of leaving one path open, so the firewall rules keep the console's address
allowed and nothing else.
"""
from __future__ import annotations

import re

# Actions, in the order the console should offer them: look first, then act.
ACTIONS: list[dict] = [
    {
        "id": "processes",
        "name": "List running processes",
        "mutating": False,
        "target": None,
        "group": "look",
        "summary": "Every process with its path, user and parent.",
        "detail": "The live list, read on the host now rather than from the last "
                  "hunt. What you check first when a finding names a process and "
                  "you need to know whether it is still there.",
    },
    {
        "id": "connections",
        "name": "List network connections",
        "mutating": False,
        "target": None,
        "group": "look",
        "summary": "Established connections and listening ports, with the owning process.",
        "detail": "Answers 'is it still talking to that address' without waiting "
                  "for another sweep.",
    },
    {
        "id": "process_tree",
        "name": "Show a process and its ancestry",
        "mutating": False,
        "target": "pid",
        "group": "look",
        "summary": "One process, its command line, and the chain of parents that started it.",
        "detail": "The parent chain is usually what turns 'suspicious binary' into "
                  "'delivered by a macro in an email'.",
    },
    {
        "id": "file_info",
        "name": "Inspect a file",
        "mutating": False,
        "target": "path",
        "group": "look",
        "summary": "Size, timestamps, hash and signature of one file.",
        "detail": "Reads the file to hash it and does not modify it. Timestamps "
                  "are reported as they are, including the access time, which "
                  "reading the file does not change on a modern Windows default.",
    },
    {
        "id": "persistence",
        "name": "List persistence entries",
        "mutating": False,
        "target": None,
        "group": "look",
        "summary": "Autoruns, services and scheduled tasks, live.",
        "detail": "The three places something arranges to come back. Worth "
                  "re-reading after you have killed something, to see whether it "
                  "is going to restart.",
    },
    {
        "id": "kill_process",
        "name": "Kill a process",
        "mutating": True,
        "target": "pid",
        "group": "act",
        "summary": "Stops one process by its id.",
        "detail": "The pid is confirmed against the process name before anything "
                  "is killed, because pids are reused and killing the wrong one "
                  "on a production host is an outage. If it has persistence, it "
                  "comes back — check persistence first.",
    },
    {
        "id": "quarantine_file",
        "name": "Quarantine a file",
        "mutating": True,
        "target": "path",
        "group": "act",
        "summary": "Moves a file somewhere it cannot run, keeping it for analysis.",
        "detail": "Moved rather than deleted, and the original path is recorded, "
                  "so it can be put back if the call was wrong and it is still "
                  "there for whoever does the analysis.",
    },
    {
        "id": "disable_account",
        "name": "Disable a local account",
        "mutating": True,
        "target": "user",
        "group": "act",
        "summary": "Stops a local account being used to log in.",
        "detail": "Disabled, not deleted: the account and its history stay for "
                  "the investigation. Refuses to touch built-in accounts, since "
                  "disabling those breaks the host rather than the intrusion.",
    },
    {
        "id": "stop_service",
        "name": "Stop a service",
        "mutating": True,
        "target": "service",
        "group": "act",
        "summary": "Stops a service and sets it not to start again.",
        "detail": "Both, because stopping a service that is set to auto-start "
                  "buys you until the next reboot and no longer.",
    },
    {
        "id": "isolate",
        "name": "Isolate the host",
        "mutating": True,
        "target": None,
        "group": "contain",
        "summary": "Cuts the host off the network, except for this console.",
        "detail": "Blocks inbound and outbound traffic with one exception: the "
                  "console's own address, so the host can still be released from "
                  "here. Without that exception, releasing it means walking to "
                  "it. Existing connections are dropped.",
    },
    {
        "id": "release",
        "name": "Release the host",
        "mutating": True,
        "target": None,
        "group": "contain",
        "summary": "Removes the isolation rules and puts the host back on the network.",
        "detail": "Removes only the rules isolation added; a firewall policy that "
                  "was there beforehand is left alone.",
    },
]

BY_ID = {a["id"]: a for a in ACTIONS}

# What a target may look like, per kind. Validated on the console side so a
# malformed value never reaches a shell on a production host.
# 1-9999999, and not zero: pid 0 is the idle/kernel process on both platforms
# and is never a containment target. Leading zeros are refused too, since a
# value like "0012" reaching a shell is a sign something else built it.
_PID = re.compile(r"^[1-9]\d{0,6}$")
_USER = re.compile(r"^[A-Za-z0-9._\\ \-]{1,64}$")
_SERVICE = re.compile(r"^[A-Za-z0-9._\- ]{1,80}$")

# Built-in accounts that must not be disabled. Disabling these does not contain
# an intrusion, it breaks the host and sometimes locks everyone out of it.
PROTECTED_ACCOUNTS = {
    "administrator", "system", "root", "localsystem", "trustedinstaller",
    "networkservice", "localservice", "defaultaccount", "wdagutilityaccount",
    "daemon", "bin", "sys", "sync", "nobody",
}

# Processes that are not a containment target: killing these takes the host
# down rather than the intrusion. A rule, not a warning, because the moment
# this is used is the moment nobody is reading warnings.
PROTECTED_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "systemd", "init",
    "kthreadd", "kernel_task",
}

# Locations quarantine must refuse, for the same reason kill refuses lsass:
# moving a file out of one of these does not contain an intrusion, it breaks
# the machine — sometimes unbootably, and always in the middle of an incident.
#
# A responder can still quarantine anything a piece of malware would plausibly
# live in, including places that look sensitive (a webshell in a web root, a
# dropped binary in /etc/cron.d). What is refused is the operating system
# itself.
PROTECTED_PATH_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/", "/lib64/",
    "/boot/", "/proc/", "/sys/", "/dev/",
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\",
)

# Individual files whose removal breaks login or boot even though their
# directory is otherwise fair game.
PROTECTED_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/fstab", "/etc/hosts",
    "/etc/sudoers", "/etc/nsswitch.conf",
}


def _protected_path(raw: str) -> bool:
    """Whether this path is part of the operating system rather than the incident.

    Normalised first so /tmp/../bin/bash is judged as /bin/bash. Traversal is
    not itself refused — an operator naming a full path is allowed to name any
    path — but it must not be a way around this list.
    """
    import posixpath

    text = (raw or "").strip().replace("\\", "/")
    windows = bool(re.match(r"^[A-Za-z]:/", text))
    normalised = posixpath.normpath(text)
    if windows:
        probe = normalised.lower().replace("/", "\\")
        return any(probe.startswith(p) for p in PROTECTED_PATH_PREFIXES)
    if normalised in PROTECTED_PATHS:
        return True
    return any(normalised.startswith(p) for p in PROTECTED_PATH_PREFIXES
               if not p.startswith("c:"))


class InvalidAction(Exception):
    """Raised with a message meant for the operator."""


def validate(action_id: str, target: str, reason: str) -> tuple[str, str]:
    """Check an action before it is queued. Returns (action_id, cleaned target)."""
    spec = BY_ID.get(action_id)
    if not spec:
        raise InvalidAction(f"'{action_id}' is not a response action.")

    target = (target or "").strip()
    kind = spec["target"]

    if kind is None:
        target = ""
    elif not target:
        raise InvalidAction(f"{spec['name']} needs a {kind}.")
    elif kind == "pid":
        if not _PID.match(target):
            raise InvalidAction("A process id is a number.")
    elif kind == "path":
        if len(target) > 400:
            raise InvalidAction("That path is too long.")
        # Newlines and shell metacharacters have no business in a path and are
        # the shape of an attempt to run something else entirely.
        if any(c in target for c in "\n\r\0;|&`$"):
            raise InvalidAction("That path contains characters a path cannot hold.")
        # Only quarantine is restricted. Reading a file's hash and signature is
        # harmless wherever it lives, and being able to inspect a system binary
        # is often the point — it is moving one that breaks the host.
        if action_id == "quarantine_file" and _protected_path(target):
            raise InvalidAction(
                f"'{target}' is part of the operating system. Quarantining it "
                "would break the host rather than contain the intrusion — "
                "inspect it instead, and contain what put it there.")
    elif kind == "user":
        if not _USER.match(target):
            raise InvalidAction("That does not look like an account name.")
        if target.split("\\")[-1].strip().lower() in PROTECTED_ACCOUNTS:
            raise InvalidAction(
                f"'{target}' is a built-in account. Disabling it breaks the host "
                "rather than containing the intrusion.")
    elif kind == "service":
        if not _SERVICE.match(target):
            raise InvalidAction("That does not look like a service name.")

    if spec["mutating"] and not (reason or "").strip():
        raise InvalidAction(
            "This changes the host, so it needs a reason. Six months from now "
            "the transcript is all anyone will have.")

    return action_id, target


def catalogue() -> list[dict]:
    return [dict(a) for a in ACTIONS]
