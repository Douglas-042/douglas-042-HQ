"""Reputation lookups for the addresses a hunt already found.

This is the second half of the indicator story, and it answers a different
question from the first.

    An indicator feed applies what you already knew.
        "Is anything from this C2 list on my hosts?"  ->  DGL-IOC, CRITICAL.

    Enrichment explains what you found.
        "This host talked to 60 external addresses. Which one first?"

Without it every address on the graph looks the same, so triage starts with
whichever one happens to be busiest — which is almost always a DNS server or a
CDN. With it, the address 340 people have reported for SSH brute force sorts
above the one that is just Windows Update.

Design decisions worth keeping:

  Verdicts are not blended.  AbuseIPDB counts complaints, VirusTotal counts
  engines, ThreatFox knows C2 infrastructure, GreyNoise knows who scans the
  whole internet. Averaging those produces a number none of them would defend.
  Each verdict is stored whole and the badge shows the worst one, with the
  provider named next to it.

  Nothing is fetched while a view renders.  A provider having a slow morning
  must never turn into a console that will not load. Lookups happen on an
  explicit action or in the background after a hunt, and every view reads the
  cache only.

  Free tiers are the real constraint.  Results are cached for twelve hours,
  each run is capped, and a daily counter stops the console before the provider
  does. Running out is reported as "the quota is spent, here is what we have",
  not as a failure of the addresses that did not get looked up.

  A rejected key is recorded against the provider, never against the address.
  A 401 says something about your configuration and nothing at all about
  whether an IP is malicious.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("douglas.enrichment")

LOOKUP_TIMEOUT = 15
# How long a verdict is treated as current. Twelve hours is a compromise: long
# enough that a day of triage costs one lookup per address, short enough that
# an address that turned bad this morning is not described by yesterday.
CACHE_HOURS = 12
# Addresses looked up in a single run. The cap exists so one busy estate cannot
# spend a whole day's free quota in a single click; the rest are picked up on
# the next run and the console says how many are waiting.
MAX_PER_RUN = 40

PROVIDERS = ("abuseipdb", "virustotal", "threatfox", "greynoise")

# What each provider is for, and what it costs. Shown in the console so nobody
# has to guess which keys are worth getting.
PROVIDER_INFO = {
    "abuseipdb": {
        "name": "AbuseIPDB",
        "asks": "How many people have reported this address, and for what",
        "free": True,
        "signup": "https://www.abuseipdb.com/register",
        "note": "Free tier: 1,000 checks a day. The single most useful key for "
                "triage — it turns an unknown address into 'reported 340 times "
                "for SSH brute force'.",
        "default_limit": 1000,
    },
    "virustotal": {
        "name": "VirusTotal",
        "asks": "How many security engines call this address malicious",
        "free": True,
        "signup": "https://www.virustotal.com/gui/join-us",
        "note": "Free tier: 500 lookups a day, 4 per minute. Broad coverage, "
                "and the vendor names are useful evidence in a report.",
        "default_limit": 500,
    },
    "threatfox": {
        "name": "ThreatFox",
        "asks": "Is this known command-and-control infrastructure, and for which malware",
        "free": True,
        "signup": "https://auth.abuse.ch/",
        "note": "Free with an abuse.ch Auth-Key. The most specific answer of "
                "the four: a hit names the malware family, not just a score.",
        "default_limit": 0,
    },
    "greynoise": {
        "name": "GreyNoise",
        "asks": "Is this scanning the whole internet, or did it come for you",
        "free": False,
        "signup": "https://viz.greynoise.io/signup",
        "note": "Paid for most use. Off by default, and never called without a "
                "key — so leaving it off costs nothing and produces no errors. "
                "Its value is subtraction: it identifies benign scanners and "
                "known-good services, taking rows off the triage list.",
        "default_limit": 0,
    },
}

# Verdict labels, worst first. Used to decide which provider's answer the badge
# shows when they disagree.
LABEL_RANK = {
    "malicious": 4,
    "suspicious": 3,
    "noise": 2,
    "unknown": 1,
    "benign": 0,
}


class EnrichmentError(Exception):
    """Raised with a message meant for the operator."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_enrichable(address: str) -> bool:
    """Public addresses only.

    A private or reserved address has no reputation to look up, and sending one
    to a third party would leak internal topology for no benefit.
    """
    try:
        ip = ipaddress.ip_address((address or "").strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved
                or ip.is_multicast or ip.is_link_local or ip.is_unspecified)


def _num(value, low: int = 0, high: int = 100, default: int = 0) -> int:
    """Read a number out of a provider response without trusting it.

    Providers return what they return. AbuseIPDB has shipped a string where a
    score belongs, and a value outside 0-100 would otherwise reach the badge
    and the sort order — a score of one billion is not a worse verdict, it is
    a broken one. Coerced and clamped so a provider having a bad day degrades
    into "no useful answer" rather than an exception or a nonsense number.
    """
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, n))


def _get(url: str, headers: dict, timeout: int = LOOKUP_TIMEOUT) -> dict:
    request = urllib.request.Request(url, headers={
        "User-Agent": "Douglas-042", "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return json.loads(resp.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("key-rejected") from exc
        if exc.code == 429:
            raise EnrichmentError("rate-limited") from exc
        if exc.code == 404:
            return {}
        raise EnrichmentError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"unreachable ({getattr(exc, 'reason', exc)})") from exc
    except json.JSONDecodeError as exc:
        raise EnrichmentError("response was not JSON") from exc


def _post(url: str, body: dict, headers: dict) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"User-Agent": "Douglas-042", "Accept": "application/json",
                 "Content-Type": "application/json", **headers},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=LOOKUP_TIMEOUT) as resp:
            return json.loads(resp.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("key-rejected") from exc
        if exc.code == 429:
            raise EnrichmentError("rate-limited") from exc
        raise EnrichmentError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"unreachable ({getattr(exc, 'reason', exc)})") from exc
    except json.JSONDecodeError as exc:
        raise EnrichmentError("response was not JSON") from exc


# ---------------------------------------------------------------------------
# Providers
#
# Each returns the same shape:
#   {"score": 0-100, "label": ..., "summary": "one line an analyst can read",
#    "detail": {...}}
# The summary matters as much as the score. "92/100" is a number; "340 reports,
# most recent 2 days ago, SSH brute force" is a reason.
# ---------------------------------------------------------------------------


def check_abuseipdb(address: str, api_key: str) -> dict:
    url = ("https://api.abuseipdb.com/api/v2/check?"
           + urllib.parse.urlencode({"ipAddress": address, "maxAgeInDays": 90}))
    payload = _get(url, {"Key": api_key})
    data = (payload or {}).get("data") or {}
    if not data:
        return {"score": 0, "label": "unknown", "summary": "No data returned.", "detail": {}}

    score = _num(data.get("abuseConfidenceScore"))
    reports = _num(data.get("totalReports"), 0, 10_000_000)
    last = (data.get("lastReportedAt") or "")[:10]

    if score >= 75:
        label = "malicious"
    elif score >= 25:
        label = "suspicious"
    elif reports > 0:
        label = "suspicious" if score >= 10 else "benign"
    else:
        label = "benign"

    bits = [f"{score}/100 confidence"]
    if reports:
        bits.append(f"{reports} report{'s' if reports != 1 else ''}")
    if last:
        bits.append(f"last {last}")
    if data.get("usageType"):
        bits.append(str(data["usageType"]))
    if data.get("isp"):
        bits.append(str(data["isp"])[:40])

    return {
        "score": score,
        "label": label,
        "summary": ", ".join(bits),
        "detail": {
            "reports": reports,
            "country": data.get("countryCode") or "",
            "isp": data.get("isp") or "",
            "usage": data.get("usageType") or "",
            "domain": data.get("domain") or "",
            "tor": bool(data.get("isTor")),
            "last_reported": last,
        },
    }


def check_virustotal(address: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(address)}"
    payload = _get(url, {"x-apikey": api_key})
    attrs = ((payload or {}).get("data") or {}).get("attributes") or {}
    if not attrs:
        return {"score": 0, "label": "unknown", "summary": "Not seen by VirusTotal.", "detail": {}}

    stats = attrs.get("last_analysis_stats") or {}
    malicious = _num(stats.get("malicious"), 0, 10_000)
    suspicious = _num(stats.get("suspicious"), 0, 10_000)
    harmless = _num(stats.get("harmless"), 0, 10_000)
    undetected = _num(stats.get("undetected"), 0, 10_000)
    total = malicious + suspicious + harmless + undetected

    # Engine counts do not map linearly onto a 0-100 feeling. A handful of
    # vendors flagging an address is already significant, so the scale is
    # steep at the bottom rather than proportional to the vendor count.
    if malicious >= 5:
        label, score = "malicious", min(100, 60 + malicious * 4)
    elif malicious >= 1:
        label, score = "suspicious", 30 + malicious * 8
    elif suspicious >= 2:
        label, score = "suspicious", 25
    else:
        label, score = "benign", 0

    bits = [f"{malicious}/{total or '?'} engines malicious"]
    if suspicious:
        bits.append(f"{suspicious} suspicious")
    if attrs.get("as_owner"):
        bits.append(str(attrs["as_owner"])[:40])
    if attrs.get("country"):
        bits.append(str(attrs["country"]))

    return {
        "score": int(score),
        "label": label,
        "summary": ", ".join(bits),
        "detail": {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "undetected": undetected,
            "as_owner": attrs.get("as_owner") or "",
            "country": attrs.get("country") or "",
            "reputation": attrs.get("reputation"),
        },
    }


def check_threatfox(address: str, api_key: str = "") -> dict:
    """abuse.ch ThreatFox: is this address known C2, and for which malware.

    The most specific of the four when it hits — a match names the malware
    family, which is a sentence an analyst can put in a report rather than a
    score they have to interpret.
    """
    headers = {"Auth-Key": api_key} if api_key else {}
    payload = _post("https://threatfox-api.abuse.ch/api/v1/",
                    {"query": "search_ioc", "search_term": address}, headers)

    status = (payload or {}).get("query_status")
    if status in ("no_result", "illegal_search_term", None):
        return {"score": 0, "label": "benign",
                "summary": "Not in ThreatFox.", "detail": {}}
    if status != "ok":
        return {"score": 0, "label": "unknown",
                "summary": f"ThreatFox: {status}", "detail": {}}

    rows = (payload or {}).get("data") or []
    if not rows:
        return {"score": 0, "label": "benign", "summary": "Not in ThreatFox.", "detail": {}}

    families, threat_types, confidences, first_seen = set(), set(), [], []
    for row in rows[:10]:
        if row.get("malware_printable"):
            families.add(str(row["malware_printable"]))
        if row.get("threat_type"):
            threat_types.add(str(row["threat_type"]))
        confidences.append(_num(row.get("confidence_level")))
        if row.get("first_seen"):
            first_seen.append(str(row["first_seen"])[:10])

    confidence = max(confidences) if confidences else 75
    # A ThreatFox hit is a positive identification of infrastructure, not a
    # popularity score, so a listing alone is already high.
    score = max(70, min(100, confidence))

    bits = []
    if families:
        bits.append("known C2: " + ", ".join(sorted(families)[:3]))
    elif threat_types:
        bits.append(", ".join(sorted(threat_types)[:2]))
    else:
        bits.append("listed as malicious infrastructure")
    if first_seen:
        bits.append(f"first seen {min(first_seen)}")

    return {
        "score": score,
        "label": "malicious",
        "summary": ", ".join(bits),
        "detail": {
            "malware": sorted(families)[:5],
            "threat_types": sorted(threat_types)[:5],
            "entries": len(rows),
            "confidence": confidence,
        },
    }


def check_greynoise(address: str, api_key: str) -> dict:
    """GreyNoise: internet-wide scanner, known-good service, or targeted.

    Paid for most use, so it is off unless someone has a key. Its value here is
    mostly subtractive: RIOT identifies common business services (Microsoft,
    Cloudflare, Google) which lets the console take an address off the triage
    list rather than adding another one to it.
    """
    payload = _get(f"https://api.greynoise.io/v3/community/{urllib.parse.quote(address)}",
                   {"key": api_key})
    if not payload or payload.get("message", "").lower().startswith("ip not observed"):
        return {"score": 0, "label": "unknown",
                "summary": "Not observed by GreyNoise.", "detail": {}}

    classification = (payload.get("classification") or "unknown").lower()
    noise = bool(payload.get("noise"))
    riot = bool(payload.get("riot"))
    name = payload.get("name") or ""
    last_seen = (payload.get("last_seen") or "")[:10]

    if classification == "malicious":
        label, score = "malicious", 80
        summary = f"Known malicious scanner{f' ({name})' if name else ''}"
    elif riot or classification == "benign":
        # A known-good service: this is the answer that removes work.
        label, score = "benign", 0
        summary = f"Known-good service{f': {name}' if name else ''}"
    elif noise:
        label, score = "noise", 20
        summary = f"Internet-wide scanner{f' ({name})' if name else ''} — not targeted at you"
    else:
        label, score = "unknown", 0
        summary = "Observed, no classification"

    if last_seen:
        summary += f", last seen {last_seen}"

    return {
        "score": score,
        "label": label,
        "summary": summary,
        "detail": {"classification": classification, "noise": noise,
                   "riot": riot, "name": name, "last_seen": last_seen},
    }


CHECKERS = {
    "abuseipdb": check_abuseipdb,
    "virustotal": check_virustotal,
    "threatfox": check_threatfox,
    "greynoise": check_greynoise,
}


# ---------------------------------------------------------------------------
# Combining
# ---------------------------------------------------------------------------


def combine(verdicts: dict) -> tuple[int, str, bool]:
    """Reduce per-provider verdicts to the badge the console shows.

    Worst-of, not average. If AbuseIPDB says 92 and VirusTotal has never heard
    of the address, the answer is 92 with AbuseIPDB's name on it — an average
    would report 46, which misrepresents both.

    known_good is tracked separately because it is not a low score, it is a
    different kind of statement: "this is Microsoft's update service" is a
    reason to stop looking, not a mild version of "this is a C2".
    """
    if not verdicts:
        return 0, "unknown", False

    best_label, best_score = "unknown", 0
    known_good = False
    for name, v in verdicts.items():
        label = (v or {}).get("label") or "unknown"
        score = _num((v or {}).get("score"))
        if label == "benign" and name == "greynoise" and (
                (v.get("detail") or {}).get("riot")):
            known_good = True
        if LABEL_RANK.get(label, 1) > LABEL_RANK.get(best_label, 1):
            best_label = label
        best_score = max(best_score, score)

    # A known-good service that nothing else flagged should not sit in the
    # middle of the list on an "unknown" label.
    if known_good and best_label in ("unknown", "noise"):
        best_label = "benign"

    return best_score, best_label, known_good


def worst_provider(verdicts: dict) -> str:
    """Which provider produced the verdict the badge is showing."""
    worst, rank, score = "", -1, -1
    for name, v in (verdicts or {}).items():
        r = LABEL_RANK.get((v or {}).get("label") or "unknown", 1)
        s = _num((v or {}).get("score"))
        if (r, s) > (rank, score):
            worst, rank, score = name, r, s
    return worst


def lookup(address: str, keys: dict) -> tuple[dict, str]:
    """Ask every configured provider about one address.

    Returns (verdicts, error). A provider that fails is left out of the
    verdicts and named in the error, so one broken key never discards the
    answers the others gave.
    """
    verdicts: dict = {}
    problems: list[str] = []

    for provider, api_key in keys.items():
        checker = CHECKERS.get(provider)
        if not checker:
            continue
        try:
            if provider == "threatfox":
                verdicts[provider] = checker(address, api_key or "")
            else:
                if not api_key:
                    continue
                verdicts[provider] = checker(address, api_key)
        except EnrichmentError as exc:
            problems.append(f"{provider}: {exc}")
        except Exception as exc:  # noqa: BLE001 - never let one provider kill a run
            logger.warning("Enrichment %s failed for %s: %s", provider, address, exc)
            problems.append(f"{provider}: unexpected error")

    return verdicts, "; ".join(problems)


def is_fresh(fetched_at, hours: int = CACHE_HOURS) -> bool:
    if not fetched_at:
        return False
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    return (utcnow() - fetched_at) < timedelta(hours=hours)
