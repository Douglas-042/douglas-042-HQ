"""Running hunts on a timetable.

A background thread wakes once a minute, finds schedules whose time has passed
and launches them. Deliberately simple: no cron parser, no job queue, no extra
dependency. An estate that needs "every third Tuesday" is better served by an
external scheduler calling the API.

The important property is that a schedule fires once. next_run_at is computed
and written before any job is created, so a slow launch or a restart mid-flight
cannot produce a double sweep.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from ..database import SessionLocal
from ..models import Agent, AuditEvent, Job, JobStatus, Schedule, new_id, utcnow

logger = logging.getLogger("douglas.schedule")

CHECK_INTERVAL_SECONDS = 60
_stop = threading.Event()
_thread: threading.Thread | None = None


def compute_next_run(schedule: Schedule, after: datetime | None = None) -> datetime:
    """When this schedule should next fire, strictly after `after`."""
    now = after or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    candidate = now.replace(hour=schedule.hour_utc, minute=0, second=0, microsecond=0)

    if schedule.frequency == "daily":
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    # Weekly: move to the requested weekday, then forward a week if it has passed.
    target = schedule.weekday if schedule.weekday is not None else 6
    delta = (target - candidate.weekday()) % 7
    candidate += timedelta(days=delta)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


def _targets(db, schedule: Schedule) -> list[Agent]:
    """Which hosts this schedule covers, resolved at fire time.

    Resolved now rather than stored, so a host enrolled after the schedule was
    written is still swept by an all-hosts schedule.
    """
    q = db.query(Agent)
    ids = schedule.agent_ids or []
    if ids:
        q = q.filter(Agent.id.in_(ids))
    # Every enrolled host is included, including offline ones: a machine that
    # was off overnight should still be swept when it comes back, and the job
    # simply waits in its queue. Excluding them would silently skip exactly the
    # hosts most worth looking at.
    return q.all()


def run_due_schedules(db, now: datetime | None = None) -> int:
    """Fire every schedule whose time has come. Returns hunts launched."""
    now = now or datetime.now(timezone.utc)
    launched = 0

    due = (
        db.query(Schedule)
        .filter(Schedule.enabled == True)  # noqa: E712
        .all()
    )

    for schedule in due:
        nxt = schedule.next_run_at
        if nxt is None:
            # First sight of this schedule: set the clock, do not fire now.
            schedule.next_run_at = compute_next_run(schedule, now)
            continue
        if nxt.tzinfo is None:
            nxt = nxt.replace(tzinfo=timezone.utc)
        if nxt > now:
            continue

        # Claim the slot before doing any work. If the launch fails or the
        # process dies here, the schedule does not fire twice.
        schedule.next_run_at = compute_next_run(schedule, now)
        schedule.last_run_at = now
        db.commit()

        try:
            agents = _targets(db, schedule)
            count = 0
            for agent in agents:
                # Never stack hunts on one host: a machine still working
                # through last week's sweep does not need another.
                busy = (
                    db.query(Job)
                    .filter(
                        Job.agent_id == agent.id,
                        Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
                    )
                    .first()
                )
                if busy:
                    continue

                db.add(Job(
                    id=new_id(),
                    agent_id=agent.id,
                    status=JobStatus.QUEUED,
                    days=schedule.days,
                    quick=schedule.quick,
                    collect_raw=schedule.collect_raw,
                    # batch_id carries the provenance: the hunts list can show
                    # which sweep a job came from without a new column.
                    batch_id=f"sched-{schedule.id}",
                ))
                count += 1

            schedule.last_run_count = count
            schedule.last_error = None
            db.add(AuditEvent(
                kind="schedule.fired",
                subject=schedule.name,
                detail=f"{count} hunts queued across {len(agents)} hosts",
            ))
            db.commit()
            launched += count
            logger.info("Schedule '%s' queued %d hunts", schedule.name, count)

        except Exception as exc:  # noqa: BLE001 - surfaced on the schedule row
            db.rollback()
            schedule.last_error = str(exc)[:400]
            db.commit()
            logger.warning("Schedule '%s' failed: %s", schedule.name, exc)

    db.commit()
    return launched


def _loop() -> None:
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            count = run_due_schedules(db)
            if count:
                from .events import broadcast
                broadcast({"type": "fleet.refresh"})
        except Exception as exc:  # pragma: no cover - keep the thread alive
            logger.warning("Scheduler pass failed: %s", exc)
        finally:
            db.close()


def start() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="douglas-scheduler", daemon=True)
    _thread.start()
    logger.info("Scheduler started")


def stop() -> None:
    _stop.set()
