"""SQLAlchemy models for the Douglas-042 hunt console."""
from __future__ import annotations

import enum
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import text
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class AgentStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    SCANNING = "scanning"
    ERROR = "error"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    UPLOADING = "uploading"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class Role(str, enum.Enum):
    """Three tiers, split by what an action costs — not by seniority.

    VIEWER reads. RESPONDER also reaches out and touches production hosts,
    which is why launching a hunt sits behind its own tier. ADMIN additionally
    controls who else gets in.
    """

    ADMIN = "admin"
    RESPONDER = "responder"
    VIEWER = "viewer"


ROLE_RANK = {Role.VIEWER: 0, Role.RESPONDER: 1, Role.ADMIN: 2}


class User(Base):
    """A console operator."""

    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=new_id)
    username = Column(String(64), unique=True, nullable=False, index=True)
    # Optional: an estate that identifies people by username alone should not
    # be blocked from creating accounts over a missing address.
    email = Column(String(255), unique=True, index=True)
    full_name = Column(String(128), default="")
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), default=Role.VIEWER, nullable=False)

    active = Column(Boolean, default=True, nullable=False)
    must_change_password = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))
    last_login = Column(DateTime(timezone=True))

    # Cheap brute-force brake. Cleared on any successful sign-in.
    failed_logins = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))

    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        until = self.locked_until
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > utcnow()

    def can(self, minimum: "Role") -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[minimum]


class Agent(Base):
    """A host running the Douglas agent."""

    __tablename__ = "agents"

    id = Column(String(32), primary_key=True, default=new_id)
    agent_key = Column(String(64), nullable=False, default=lambda: secrets.token_hex(32))

    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64))
    domain = Column(String(255))
    domain_role = Column(String(64))
    # windows | linux. Decides which collector and bootstrap the console serves;
    # a Linux host handed a PowerShell script fails in a way that looks like a
    # network problem rather than a mismatch.
    platform = Column(String(16), default="windows", index=True)
    os_caption = Column(String(255))

    # What this host can actually run, reported by the agent rather than
    # assumed from the platform.
    #
    # Two hosts running the same distribution can differ on whether auditd is
    # installed, whether it has rules loaded, and whether a YARA binary exists
    # — and each of those decides whether a whole class of detection produces
    # findings or silently produces nothing. Silence is the dangerous case:
    # a sweep that could not look returns the same empty result as a sweep that
    # looked and found nothing, and only one of those means the host is clean.
    # Recorded here so the console can say which it was.
    capabilities = Column(JSON, default=dict)
    capabilities_at = Column(DateTime(timezone=True))
    os_build = Column(String(64))
    architecture = Column(String(32))
    ps_version = Column(String(32))
    agent_version = Column(String(32))
    tags = Column(JSON, default=list)

    status = Column(Enum(AgentStatus), default=AgentStatus.ONLINE, index=True)
    last_seen = Column(DateTime(timezone=True), default=utcnow, index=True)
    enrolled_at = Column(DateTime(timezone=True), default=utcnow)

    # Rolling summary of the most recent completed scan
    last_scan_at = Column(DateTime(timezone=True))
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="UNKNOWN")
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    jobs = relationship("Job", back_populates="agent", cascade="all, delete-orphan")

    def is_stale(self, timeout_seconds: int) -> bool:
        if not self.last_seen:
            return True
        seen = self.last_seen
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return (utcnow() - seen).total_seconds() > timeout_seconds


class Job(Base):
    """A hunt dispatched to one agent."""

    __tablename__ = "jobs"

    id = Column(String(32), primary_key=True, default=new_id)
    agent_id = Column(String(32), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    batch_id = Column(String(32), index=True)

    status = Column(Enum(JobStatus), default=JobStatus.QUEUED, index=True)

    # Scan parameters handed to Douglas-042.ps1
    days = Column(Integer, default=14)
    quick = Column(Boolean, default=False)
    collect_raw = Column(Boolean, default=False)
    no_resolve = Column(Boolean, default=False)
    max_events = Column(Integer, default=100000)

    # Per-hunt detection choices. Sigma over 2400 rules and YARA over every
    # recent file are the two expensive parts of a sweep; on a triage run an
    # operator wants them off rather than waiting for them.
    use_sigma = Column(Boolean, default=True, nullable=False)
    use_yara = Column(Boolean, default=True, nullable=False)
    use_custom = Column(Boolean, default=True, nullable=False)
    # Findings below this are collected but not reported, which keeps a
    # triage sweep readable without changing what was looked at.
    min_severity = Column(String(16), default="INFO")
    # server | workstation | webserver | dc | auto
    profile = Column(String(20), default="auto")
    ioc_list = Column(Text)

    # Live progress
    progress = Column(Float, default=0.0)
    phase = Column(String(64), default="")
    phase_detail = Column(String(255), default="")
    modules_done = Column(Integer, default=0)
    modules_total = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    dispatched_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)

    error = Column(Text)

    # Result summary
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16))
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    # How many findings a standing suppression hid on this run. Shown so a
    # quiet result is never mistaken for a clean one.
    suppressed_count = Column(Integer, default=0)

    # Compact network and process snapshot for the graph view. Stored on the
    # job rather than parsed from the bundle so the view works even when raw
    # evidence was not uploaded.
    graph = Column(JSON)

    # A rolling log of module-level events the agent reports while a hunt runs:
    # which module finished, how long it took, how many rows and findings it
    # produced. Kept on the job so the console can replay the live sweep and so
    # a browser opening the hunts view mid-run sees the activity so far, not a
    # bare progress bar. Read by jobs.py; without this column, launching a hunt
    # raised a 500 the moment the first progress post arrived.
    activity = Column(JSON, default=list)

    manifest = Column(JSON)
    module_stats = Column(JSON)
    collection_errors = Column(JSON)
    bundle_path = Column(String(512))
    bundle_size = Column(Integer)

    agent = relationship("Agent", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    timeline = relationship("TimelineEvent", back_populates="job", cascade="all, delete-orphan")

    @property
    def hostname(self) -> str:
        return self.agent.hostname if self.agent else "unknown"


class FindingStatus(str, enum.Enum):
    """Where a finding sits in triage.

    OPEN is the only state that should draw attention. Everything else is a
    decision someone made and can be audited later.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


# States that no longer need an analyst's attention.
CLOSED_STATUSES = {
    FindingStatus.TRUE_POSITIVE,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.SUPPRESSED,
}


class Suppression(Base):
    """A standing decision to stop showing a finding.

    Without this the tool is single-use: the same 300 findings come back on
    every scan and by the third one nobody reads the list. With it, tuning
    accumulates.

    A reason is required. A suppression with no rationale is indistinguishable
    from someone hiding a real detection, and six months later nobody can tell
    which it was.
    """

    __tablename__ = "suppressions"

    id = Column(String(32), primary_key=True, default=new_id)
    rule_id = Column(String(32), nullable=False, index=True)

    # Optional narrowing. Empty means "this rule, everywhere".
    evidence_contains = Column(String(400))
    hostname = Column(String(255), index=True)

    reason = Column(Text, nullable=False)
    active = Column(Boolean, default=True, nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))
    # How many findings this has hidden. A suppression covering thousands is
    # usually a mistake, and the number is the only way to notice.
    match_count = Column(Integer, default=0)
    last_matched_at = Column(DateTime(timezone=True))

    def matches(self, rule_id: str, evidence: str, hostname: str) -> bool:
        if not self.active or self.rule_id != rule_id:
            return False
        if self.hostname and self.hostname != hostname:
            return False
        if self.evidence_contains:
            return self.evidence_contains.lower() in (evidence or "").lower()
        return True

    @property
    def scope(self) -> str:
        if self.hostname and self.evidence_contains:
            return "host and evidence"
        if self.hostname:
            return "one host"
        if self.evidence_contains:
            return "matching evidence"
        return "fleet-wide"


class Finding(Base):
    """One triage finding produced by the scanner's rule engine."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(32), ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    agent_id = Column(String(32), index=True)
    hostname = Column(String(255), index=True)

    rule_id = Column(String(32), index=True)
    severity = Column(String(16), index=True)
    title = Column(String(512))
    evidence = Column(Text)
    mitre = Column(String(32), index=True)
    why = Column(Text)
    artifact = Column(String(128))
    occurred_at = Column(String(64))

    acknowledged = Column(Boolean, default=False)
    note = Column(Text)

    # --- Triage ---------------------------------------------------------
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN,
                    nullable=False, index=True)
    assignee = Column(String(64), index=True)
    status_changed_at = Column(DateTime(timezone=True))
    status_changed_by = Column(String(64))
    # Set when a suppression rule hid this finding, so the decision is
    # traceable back to who wrote the rule and why.
    suppressed_by = Column(String(32), index=True)

    # Position of this finding in the hunt that produced it, counted from one.
    #
    # Findings now arrive twice: streamed while the sweep runs so the console
    # fills in live, and again in the bundle uploaded at the end. Both come
    # from the same append-ordered source, so the position identifies a finding
    # across the two and the upload can skip what already landed. Without it
    # every live finding would appear a second time when the hunt finished.
    #
    # Null for findings from an older agent that streams nothing; those only
    # ever arrive once, so there is nothing to reconcile.
    seq = Column(Integer)

    job = relationship("Job", back_populates="findings")


Index("ix_findings_sev_job", Finding.severity, Finding.job_id)
# One row per position per hunt. The guard is in the database rather than in
# the ingest path because a retried progress post is normal — an agent that
# loses its connection mid-post will send the same findings again.
Index("ux_findings_job_seq", Finding.job_id, Finding.seq, unique=True,
      sqlite_where=text("seq IS NOT NULL"))


class TimelineEvent(Base):
    """A time-ordered event from the scanner's unified timeline."""

    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(32), ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    hostname = Column(String(255), index=True)

    time_utc = Column(String(64), index=True)
    source = Column(String(64))
    severity = Column(String(16), index=True)
    description = Column(Text)
    detail = Column(Text)

    job = relationship("Job", back_populates="timeline")


class EnrollmentToken(Base):
    """Shared secret an agent presents once to join the fleet."""

    __tablename__ = "enrollment_tokens"

    token = Column(String(64), primary_key=True, default=lambda: secrets.token_urlsafe(32))
    label = Column(String(128), default="default")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    revoked = Column(Boolean, default=False)
    uses = Column(Integer, default=0)


class SigmaRule(Base):
    """A community detection rule, stored compiled and ready to ship.

    Compiling on upload rather than on every dispatch means a broken rule is
    rejected while someone is looking at the screen, not silently at 3am when
    an agent asks for the ruleset.
    """

    __tablename__ = "sigma_rules"

    id = Column(String(64), primary_key=True)
    title = Column(String(300), nullable=False)
    description = Column(Text)
    author = Column(String(200))
    level = Column(String(16), index=True)
    severity = Column(String(16))
    status = Column(String(32))
    channel = Column(String(128), index=True)
    event_ids = Column(JSON, default=list)
    # windows | linux. Decides which hosts get the rule: the two read entirely
    # different sources, and a rule shipped to the wrong one is a detection
    # that can never fire while looking like it is loaded.
    platform = Column(String(16), default="windows", index=True)
    tags = Column(JSON, default=list)
    mitre = Column(String(32), index=True)
    falsepositives = Column(JSON, default=list)
    references = Column(JSON, default=list)

    # The compiled plan the agent executes.
    selections = Column(JSON, nullable=False)
    condition = Column(JSON, nullable=False)
    condition_text = Column(Text)

    enabled = Column(Boolean, default=True, nullable=False, index=True)
    source = Column(String(512))
    added_at = Column(DateTime(timezone=True), default=utcnow)
    added_by = Column(String(64))


class YaraRule(Base):
    """A YARA rule compiled to string matching the agent can run.

    Same shape as SigmaRule for the same reason: compile once where it can be
    validated, ship a plan, keep the agent simple.
    """

    __tablename__ = "yara_rules"

    id = Column(String(64), primary_key=True)
    name = Column(String(300), nullable=False, index=True)
    description = Column(Text)
    author = Column(String(200))
    reference = Column(String(300))
    severity = Column(String(16), index=True)
    tags = Column(JSON, default=list)

    strings = Column(JSON, nullable=False)
    condition = Column(JSON, nullable=False)
    condition_text = Column(Text)
    filesize_min = Column(Integer)
    filesize_max = Column(Integer)

    enabled = Column(Boolean, default=True, nullable=False, index=True)
    source = Column(String(512))
    added_at = Column(DateTime(timezone=True), default=utcnow)
    added_by = Column(String(64))


class Schedule(Base):
    """A standing instruction to hunt on a timetable.

    This is what separates hunting from incident response. A second scan is
    only worth running if something compares it to the first, so schedules and
    the diff view are two halves of one feature.
    """

    __tablename__ = "schedules"

    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(200), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)

    # daily | weekly
    frequency = Column(String(16), default="weekly", nullable=False)
    hour_utc = Column(Integer, default=2, nullable=False)
    weekday = Column(Integer, default=6)  # 0=Monday .. 6=Sunday, weekly only

    # Empty list means every reachable host at the time it fires.
    agent_ids = Column(JSON, default=list)
    days = Column(Integer, default=14, nullable=False)
    quick = Column(Boolean, default=False, nullable=False)
    collect_raw = Column(Boolean, default=False, nullable=False)

    last_run_at = Column(DateTime(timezone=True))
    last_run_count = Column(Integer, default=0)
    last_error = Column(Text)
    next_run_at = Column(DateTime(timezone=True), index=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))

    @property
    def summary(self) -> str:
        when = f"{self.hour_utc:02d}:00 UTC"
        if self.frequency == "daily":
            return f"Every day at {when}"
        days = ["Monday", "Tuesday", "Wednesday", "Thursday",
                "Friday", "Saturday", "Sunday"]
        label = days[self.weekday] if self.weekday is not None and 0 <= self.weekday < 7 else "Sunday"
        return f"Every {label} at {when}"


class CustomRule(Base):
    """A detection an operator wrote in the console.

    Runs against the artifact tables the collector produces, which is the half
    of the detection surface Sigma and YARA cannot reach.
    """

    __tablename__ = "custom_rules"

    id = Column(String(32), primary_key=True, default=new_id)
    rule_id = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    severity = Column(String(16), nullable=False)
    mitre = Column(String(32))
    why = Column(Text)

    artifact = Column(String(64), nullable=False, index=True)
    match = Column(String(8), default="all", nullable=False)
    conditions = Column(JSON, nullable=False)

    enabled = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))
    updated_at = Column(DateTime(timezone=True))


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    CONTAINED = "contained"
    CLOSED = "closed"


class Case(Base):
    """One incident, holding the hosts and indicators that belong to it.

    Without this every hunt is its own island. A real engagement is forty hosts,
    one indicator list and one report; the console had no way to say that two
    hosts were part of the same story.
    """

    __tablename__ = "cases"

    id = Column(String(32), primary_key=True, default=new_id)
    reference = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False)
    status = Column(Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False, index=True)
    severity = Column(String(16), default="HIGH")

    summary = Column(Text)
    lead = Column(String(64))

    # Hosts in scope and the indicator list for the whole engagement, so a new
    # host joining picks up the same indicators as the rest.
    agent_ids = Column(JSON, default=list)
    iocs = Column(JSON, default=list)

    opened_at = Column(DateTime(timezone=True), default=utcnow)
    closed_at = Column(DateTime(timezone=True))
    created_by = Column(String(64))


class CaseNote(Base):
    """An entry in a case's running log."""

    __tablename__ = "case_notes"

    id = Column(String(32), primary_key=True, default=new_id)
    case_id = Column(String(32), ForeignKey("cases.id"), nullable=False, index=True)
    body = Column(Text, nullable=False)
    author = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class IocFeed(Base):
    """An external source of indicators, refreshed on demand.

    Indicators are cached here rather than fetched at hunt time: a feed that is
    slow or unreachable must not delay or fail a sweep, and an isolated console
    should still hunt with whatever was last pulled.
    """

    __tablename__ = "ioc_feeds"

    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(200), nullable=False)
    kind = Column(String(16), default="http", nullable=False)  # http | misp
    url = Column(String(1000), nullable=False)

    # What this feed is FOR, which decides whether its values ever touch a host:
    #
    #   indicators  Known-bad values — C2 IPs, malware hashes, malicious URLs.
    #               Merged into the hunt pool and sent to every host, where the
    #               collector matches them against live connections, processes,
    #               DNS and files. A match is a DGL-IOC finding: "this host
    #               talked to a known C2".
    #
    #   watch       Values that describe victims, not attackers — leak-site
    #               domains, ransomware victim lists. These must NEVER go to a
    #               host: a machine that browses a listed company's site would
    #               be flagged CRITICAL for it. Instead the console watches this
    #               list for the organisation's own names appearing on it.
    #
    # The distinction is the whole reason a victim feed (ransomware.live) and a
    # C2 feed (Feodo, URLhaus, ThreatFox) can coexist without one poisoning the
    # other. classify() still routes by value shape, but the mode is the guard
    # rail: a watch feed's values are kept out of the pool regardless.
    mode = Column(String(16), default="indicators", nullable=False)

    api_key = Column(String(500))
    header_name = Column(String(120))     # http: which header carries the key
    tags = Column(String(500))            # misp: comma-separated tag filter
    days = Column(Integer, default=30)    # misp: lookback
    verify_tls = Column(Boolean, default=True, nullable=False)

    enabled = Column(Boolean, default=True, nullable=False, index=True)
    auto_include = Column(Boolean, default=True, nullable=False)

    indicators = Column(JSON, default=list)
    indicator_count = Column(Integer, default=0)
    breakdown = Column(JSON, default=dict)

    # watch mode only: the terms an operator wants to be told about if they
    # appear in this feed (their own domains, brand names), and the hits found
    # on the last refresh so the console can surface them.
    watch_terms = Column(Text)             # comma/newline separated
    watch_hits = Column(JSON, default=list)

    last_fetch_at = Column(DateTime(timezone=True))
    last_error = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))


class Integration(Base):
    """Somewhere findings get forwarded to, such as Wazuh."""

    __tablename__ = "integrations"

    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(200), nullable=False)
    kind = Column(String(32), default="wazuh", nullable=False)
    transport = Column(String(16), default="http", nullable=False)  # http | syslog

    url = Column(String(1000))          # http
    host = Column(String(255))          # syslog and email
    port = Column(Integer, default=514)
    api_key = Column(String(500))       # doubles as the SMTP password
    verify_tls = Column(Boolean, default=True, nullable=False)

    # Which dialect the destination speaks: json (Wazuh and generic),
    # splunk (HEC), leef (QRadar), cef (ArcSight), ndjson.
    format = Column(String(16), default="json", nullable=False)
    index_name = Column(String(120))    # splunk
    sourcetype = Column(String(120))    # splunk

    # email
    recipients = Column(String(1000))
    mail_from = Column(String(255))
    mail_user = Column(String(255))
    use_tls = Column(Boolean, default=True, nullable=False)
    use_ssl = Column(Boolean, default=False, nullable=False)

    # Anything below this is not worth waking a SIEM for.
    min_severity = Column(String(16), default="MEDIUM", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)

    sent_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    last_attempt_at = Column(DateTime(timezone=True))
    last_success_at = Column(DateTime(timezone=True))
    last_error = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))


class ApiToken(Base):
    """A bearer token for scripts and other tools.

    Only the fingerprint is stored. A leaked database gives an attacker the
    ability to see that tokens exist, not to use them.
    """

    __tablename__ = "api_tokens"

    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(200), nullable=False)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    prefix = Column(String(16))          # shown in the list so tokens are identifiable
    role = Column(Enum(Role), default=Role.VIEWER, nullable=False)

    enabled = Column(Boolean, default=True, nullable=False, index=True)
    last_used_at = Column(DateTime(timezone=True))
    use_count = Column(Integer, default=0)
    expires_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String(64))


class EnrichmentKey(Base):
    """An API key for a reputation provider, plus how that provider is doing.

    Kept per provider rather than in one settings blob so a rejected key is
    recorded against the provider that rejected it. Attaching that failure to
    an address instead would read as a verdict about the address, which is the
    opposite of the truth: a 401 says nothing about whether an IP is malicious.

    Providers are opt-in. One with no key and enabled off is simply never
    called, so a paid provider nobody subscribes to costs nothing and produces
    no errors — it just sits there until someone has a key for it.
    """

    __tablename__ = "enrichment_keys"

    provider = Column(String(32), primary_key=True)   # abuseipdb | virustotal | threatfox | greynoise
    api_key = Column(String(500))
    enabled = Column(Boolean, default=False, nullable=False)

    # Free tiers are small and easy to burn through. Counted here so the
    # console can stop before the provider does, and say why it stopped.
    calls_today = Column(Integer, default=0)
    calls_date = Column(String(10), default="")       # YYYY-MM-DD the count belongs to
    daily_limit = Column(Integer, default=0)          # 0 = no limit configured

    last_used_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
    ok_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)

    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))


class IpReputation(Base):
    """What the reputation providers said about one address, cached.

    Cached because the free tiers are the constraint that decides whether this
    feature is usable at all: re-asking on every graph render would exhaust a
    day's quota in one sitting. Nothing here is ever fetched while a view is
    rendering — enrichment is an explicit step, and the graph only reads what
    is already stored.

    Each provider's verdict is kept whole rather than averaged into one number.
    They measure different things — how many people complained, how many
    engines flagged it, whether it is a known C2, whether it scans everyone —
    and a mean of those is a figure none of them would stand behind.
    """

    __tablename__ = "ip_reputation"

    address = Column(String(64), primary_key=True)
    # {provider: {score, label, summary, detail}}
    verdicts = Column(JSON, default=dict)
    # The worst verdict across providers, which is what the badge shows.
    score = Column(Integer, default=0)                 # 0-100
    label = Column(String(24), default="unknown")      # malicious|suspicious|benign|noise|unknown
    # GreyNoise calling something a known-good service is worth as much as a
    # bad verdict: it takes a row off the triage list.
    is_known_good = Column(Boolean, default=False)

    fetched_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    error = Column(Text)


class RuleState(Base):
    """Whether one built-in DGL rule is switched on.

    Suppression and disabling look similar and are not the same thing, and the
    difference matters when someone reads the result six months later:

        A suppression says "this fired, and we decided it does not matter here".
        The finding is recorded, counted, and attributed to a standing decision
        with a written reason.

        Disabling says "do not run this check at all". Nothing is produced, so
        there is nothing to review and no reason recorded against any finding.

    Disabling is the blunter tool and belongs to whole categories of noise —
    the collection-integrity rules on an estate that knowingly keeps 7 days of
    logs, say. Suppression is for a specific pattern on a specific host.

    Only rows for rules somebody has actually turned off exist; a rule with no
    row is on. That way the default is "every detection runs", and the table
    stays a short list of deliberate exceptions rather than a mirror of the
    catalogue that has to be kept in step with it.
    """

    __tablename__ = "rule_states"

    rule_id = Column(String(32), primary_key=True)
    enabled = Column(Boolean, default=True, nullable=False)
    # Not required the way a suppression's reason is: switching off a whole
    # category is usually self-explanatory, and demanding prose for each of
    # sixteen rules would just produce sixteen copies of the same sentence.
    note = Column(Text)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))


class ResponseAction(Base):
    """One incident-response command sent to a host.

    Separate from Job because the two are not the same kind of work and should
    not share a queue. A hunt is long, read-only and produces findings. A
    response action is short, often changes the host, and produces a transcript
    somebody will read line by line — usually while deciding what to do next.

    Everything about the design assumes the worst moment it will be used in:
    someone is mid-incident, on a production host, and cannot undo a mistake.
    So each action records who asked for it and why, actions that change the
    host are marked as such, and the full output is kept whether it succeeded
    or not — a failed containment attempt is exactly the thing you need the
    transcript of.
    """

    __tablename__ = "response_actions"

    id = Column(String(32), primary_key=True, default=new_id)
    agent_id = Column(String(32), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    hostname = Column(String(255))

    action = Column(String(32), nullable=False, index=True)
    # Free-form per action: a pid, a path, a username.
    target = Column(String(500))
    # queued | running | completed | failed | cancelled
    status = Column(String(16), default="queued", nullable=False, index=True)

    # Whether this changes the host. Read-only actions are the ones people run
    # without thinking, which is fine — but the console must not present the
    # two identically.
    mutating = Column(Boolean, default=False, nullable=False)

    # The reason is required for anything that changes a host. Six months later
    # "who isolated this server and why" needs an answer that is not a guess.
    reason = Column(Text)

    output = Column(Text)
    error = Column(Text)
    exit_code = Column(Integer)

    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    dispatched_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)
    created_by = Column(String(64))

    __table_args__ = (
        # One outstanding action per host, enforced by the database rather than
        # by a check in the router. Two requests arriving together both passed
        # that check and both queued, which is how a host ends up isolated
        # twice or killed and quarantined in an order nobody chose.
        Index(
            "ux_response_one_per_agent",
            "agent_id",
            unique=True,
            sqlite_where=text("status IN ('queued','running')"),
        ),
    )


class Setting(Base):
    """Small key/value store for things an admin changes at runtime.

    The console address lives here rather than only in the environment, so an
    operator can correct it from the UI without editing a file and restarting
    the service mid-incident.
    """

    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))


def get_setting(db, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if row and row.value else default


def set_setting(db, key: str, value: str, who: str = "") -> None:
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.add(row)
    row.value = value
    row.updated_by = who
    row.updated_at = utcnow()


class AuditEvent(Base):
    """Console-side activity trail."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    at = Column(DateTime(timezone=True), default=utcnow, index=True)
    kind = Column(String(32), index=True)
    subject = Column(String(255))
    detail = Column(Text)
