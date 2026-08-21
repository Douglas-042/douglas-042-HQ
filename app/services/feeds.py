"""Pulling indicators from external feeds.

An analyst who has to paste a list before every hunt will stop pasting lists.
This fetches them instead: a plain URL, a JSON API, or a MISP instance.

Everything is normalised to the same shape the manual paste box produces, so
the rest of the platform does not care where an indicator came from. What it
does record is the source, because six months later "why did we flag this
address" is a question with a real answer only if provenance survived.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("douglas.feeds")

FETCH_TIMEOUT = 60
MAX_BYTES = 25 * 1024 * 1024
MAX_INDICATORS = 200_000

# Same recognisers the console's file import uses, so a feed and a pasted list
# behave identically.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("md5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("ipv4", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
    ("url", re.compile(r"^https?://\S{4,}$", re.I)),
    # Before the domain rule: "dropper.exe" is shaped exactly like a domain and
    # would otherwise be classified as one, which changes what it is matched
    # against on the host.
    ("filename", re.compile(r"^[\w.\-]+\.(exe|dll|ps1|bat|scr|vbs|js|jse|vbe|"
                            r"jar|sys|hta|cmd|msi|lnk|wsf)$", re.I)),
    # A .onion address is a leak-site / victim marker, never something a normal
    # host connects to. Recognised as its own kind so a watch feed can pull it
    # while the pool never carries it — matching .onion against a host would be
    # meaningless. Must sit before the domain rule, which would otherwise claim it.
    ("onion", re.compile(r"^([a-z2-7]{16}|[a-z2-7]{56})\.onion$", re.I)),
    ("domain", re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")),
]

# Addresses that would match everything or nothing useful. A feed containing
# 127.0.0.1 or 8.8.8.8 will otherwise light up the whole estate.
_USELESS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4",
    "localhost", "example.com", "google.com", "microsoft.com", "windows.com",
}


class FeedError(Exception):
    """Raised with a message meant for the operator, not a stack trace."""


def normalise(value: str) -> str:
    """Reshape a raw feed value into the form the collector matches against.

    The one that matters in practice is ThreatFox's most useful indicator,
    which arrives as ip:port (185.220.101.50:443). On the host the connection
    table has the address and port in separate columns, so the combined form
    never matches anything — the address has to be split out. A bare host:port
    on a domain is treated the same way. URLs are left untouched, because their
    path and port are part of what makes them a URL.
    """
    v = (value or "").strip().strip("\"'")
    if not v:
        return v
    if "://" in v:
        return v  # a URL — leave port and path intact
    # ip:port or domain:port -> strip the port; the collector matches host and
    # port separately and the combined token matches neither.
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$", v)
    if m:
        return m.group(1)
    m = re.match(r"^([a-zA-Z0-9.\-]+):\d{1,5}$", v)
    if m and "." in m.group(1):
        return m.group(1)
    return v


def classify(value: str) -> str | None:
    v = normalise(value)
    if not v or len(v) > 400 or v.startswith("#"):
        return None
    if v.lower() in _USELESS:
        return None
    for kind, pattern in _PATTERNS:
        if pattern.match(v):
            if kind == "ipv4":
                try:
                    ip = ipaddress.ip_address(v)
                    # Private and reserved space in a threat feed is a mistake
                    # in the feed, and acting on it would flag the whole LAN.
                    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                        return None
                except ValueError:
                    return None
            return kind
    return None


def _http_get(url: str, headers: dict | None = None) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": "Douglas-042", "Accept": "*/*", **(headers or {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise FeedError(
                f"The feed rejected the request ({exc.code}). Check the API key."
            ) from exc
        if exc.code == 404:
            raise FeedError("The feed URL returned 404. Check the address.") from exc
        raise FeedError(f"The feed returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise FeedError(
            f"Could not reach the feed ({getattr(exc, 'reason', exc)}). This console "
            "is often run without internet access; paste or upload the list instead."
        ) from exc

    if len(data) > MAX_BYTES:
        raise FeedError(f"The feed exceeds the {MAX_BYTES // (1024 * 1024)} MB limit.")
    return data


def _walk_json(node, out: set) -> None:
    """Pull anything indicator-shaped out of arbitrary JSON.

    Feeds disagree about field names — value, indicator, ioc, ip, domain — so
    rather than maintaining a mapping per provider, every string in the
    document is offered to the classifier.
    """
    if isinstance(node, str):
        if classify(node):
            # Store the normalised form (ip:port -> ip), not the raw string,
            # so what lands in the pool is what the host can actually match.
            out.add(normalise(node))
    elif isinstance(node, dict):
        for value in node.values():
            _walk_json(value, out)
    elif isinstance(node, list):
        for value in node:
            _walk_json(value, out)


def _from_text(text: str) -> set:
    found = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        if classify(line):
            found.add(normalise(line))
            continue
        # CSV and TSV rows: offer each column.
        for part in re.split(r"[,;\t|]", line):
            part = part.strip().strip("\"'")
            if classify(part):
                found.add(normalise(part))
    return found


def fetch_http(url: str, api_key: str = "", header_name: str = "") -> set:
    """A URL returning JSON or plain text."""
    headers = {}
    if api_key:
        if header_name:
            headers[header_name] = api_key
        else:
            headers["Authorization"] = f"Bearer {api_key}"

    raw = _http_get(url, headers)
    text = raw.decode("utf-8", errors="replace")

    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            found: set = set()
            _walk_json(json.loads(text), found)
            return found
        except json.JSONDecodeError:
            pass  # fall through and read it as text
    return _from_text(text)


def fetch_misp(base_url: str, api_key: str, days: int = 30,
               tags: str = "", verify_tls: bool = True) -> set:
    """MISP, via its restSearch endpoint.

    Asks for attributes rather than whole events: the platform matches values,
    and pulling full events would return megabytes of context nothing here
    reads.
    """
    if not api_key:
        raise FeedError("MISP needs an API key.")

    url = base_url.rstrip("/") + "/attributes/restSearch"
    body = {
        "returnFormat": "json",
        "last": f"{max(1, days)}d",
        "to_ids": True,          # only attributes MISP marks as actionable
        "enforceWarninglist": True,  # let MISP drop its own known-good list
        "limit": 50_000,
    }
    if tags.strip():
        body["tags"] = [t.strip() for t in tags.split(",") if t.strip()]

    request = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Douglas-042",
        }, method="POST")

    ctx = None
    if not verify_tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT, context=ctx) as resp:
            payload = json.loads(resp.read(MAX_BYTES + 1))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise FeedError("MISP rejected the API key.") from exc
        raise FeedError(f"MISP returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise FeedError(
            f"Could not reach MISP ({getattr(exc, 'reason', exc)})."
        ) from exc
    except json.JSONDecodeError as exc:
        raise FeedError("MISP returned something that is not JSON.") from exc

    attributes = (payload.get("response") or {}).get("Attribute") or []
    found = set()
    for attr in attributes:
        value = attr.get("value")
        if value and classify(value):
            found.add(normalise(value))
    return found


# ---------------------------------------------------------------------------
# Watch mode
#
# A watch feed answers the opposite question to an indicator feed. Instead of
# "is anything from this list on my hosts", it asks "is my name on this list" —
# the list being ransomware victims, leak-site postings, breach dumps. Its
# values describe victims, so they must never reach a host: a machine visiting
# a listed company's website would otherwise be flagged for connecting to a
# "malicious" domain. Nothing here goes into the pool; the console just scans
# the pulled text for the operator's own terms and reports where they appear.
# ---------------------------------------------------------------------------


def _raw_strings(node, out: list, limit: int = 200_000) -> None:
    """Every string in an arbitrary JSON document, for substring watching."""
    if len(out) >= limit:
        return
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            _raw_strings(value, out, limit)
    elif isinstance(node, list):
        for value in node:
            _raw_strings(value, out, limit)


def fetch_watch(feed) -> tuple[list[str], list[dict]]:
    """Pull a watch feed and match it against the operator's terms.

    Returns (haystack_sample, hits). The sample is a few representative lines
    kept only so the operator can see the feed is returning data; the hits are
    the matches that matter — each records the term and the line it was found
    on, so "your brand appears here" comes with the context to verify it.
    """
    kind = (feed.kind or "http").lower()
    if kind == "misp":
        raw = _misp_raw(feed)
    else:
        raw = _http_get(feed.url, _http_headers(feed.api_key or "", feed.header_name or ""))
        raw = raw.decode("utf-8", errors="replace")

    # Break into searchable lines whether the source is JSON or text.
    lines: list[str] = []
    stripped = raw.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            strings: list = []
            _raw_strings(json.loads(raw), strings)
            lines = [s for s in strings if s and len(s) < 2000]
        except json.JSONDecodeError:
            lines = raw.splitlines()
    else:
        lines = raw.splitlines()

    terms = _watch_terms(feed.watch_terms or "")
    hits: list[dict] = []
    if terms:
        seen: set = set()
        for line in lines:
            low = line.lower()
            for term in terms:
                if term in low:
                    key = (term, line.strip()[:200])
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append({"term": term, "context": line.strip()[:200]})
                    if len(hits) >= 200:
                        break
            if len(hits) >= 200:
                break

    sample = [l.strip()[:120] for l in lines if l.strip()][:15]
    return sample, hits


def _watch_terms(raw: str) -> list[str]:
    parts = re.split(r"[,\n;]", raw or "")
    return [p.strip().lower() for p in parts if p.strip() and len(p.strip()) >= 3]


def _http_headers(api_key: str, header_name: str) -> dict:
    if not api_key:
        return {}
    if header_name:
        return {header_name: api_key}
    return {"Authorization": f"Bearer {api_key}"}


def _misp_raw(feed) -> str:
    """The raw MISP response body, for watch scanning rather than indicators."""
    url = feed.url.rstrip("/") + "/attributes/restSearch"
    body = {"returnFormat": "json", "last": f"{max(1, feed.days or 30)}d", "limit": 50_000}
    if (feed.tags or "").strip():
        body["tags"] = [t.strip() for t in feed.tags.split(",") if t.strip()]
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Authorization": feed.api_key or "", "Accept": "application/json",
                 "Content-Type": "application/json", "User-Agent": "Douglas-042"},
        method="POST")
    ctx = None
    if not feed.verify_tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT, context=ctx) as resp:
            return resp.read(MAX_BYTES + 1).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise FeedError("MISP rejected the API key.") from exc
        raise FeedError(f"MISP returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"Could not reach MISP ({getattr(exc, 'reason', exc)}).") from exc


def fetch(feed) -> tuple[set, dict]:
    """Fetch one feed. Returns (indicators, breakdown by kind).

    Indicator feeds only. A watch feed goes through fetch_watch instead, and
    its values are deliberately never returned here so they cannot reach the
    pool or a host.
    """
    kind = (feed.kind or "http").lower()
    if kind == "misp":
        values = fetch_misp(feed.url, feed.api_key or "", feed.days or 30,
                            feed.tags or "", bool(feed.verify_tls))
    else:
        values = fetch_http(feed.url, feed.api_key or "", feed.header_name or "")

    if len(values) > MAX_INDICATORS:
        raise FeedError(
            f"The feed returned {len(values)} indicators; the limit is {MAX_INDICATORS}. "
            "Narrow it with a tag or a shorter window."
        )

    breakdown: dict[str, int] = {}
    for value in values:
        k = classify(value)
        if k:
            breakdown[k] = breakdown.get(k, 0) + 1
    return values, breakdown
