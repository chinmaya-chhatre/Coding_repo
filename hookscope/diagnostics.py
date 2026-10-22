"""Explain why a signature check failed, in terms a person can act on.

``verify`` says *that* a delivery failed ("signature mismatch"). ``diagnose`` looks at what arrived and
says *why* it probably failed and what to change. It runs only for deliveries the verifier rejected
(``invalid`` or ``unsigned``), never for good ones and never for ``no_secret``, which is a HookScope
setting rather than something the sender got wrong.

Each detector is a small function registered with ``@detector``. They run in order and the first one
that recognises the problem wins, so specific detectors go before general ones. A detector returns a
``Diagnosis``, or ``None`` when the problem is not the one it knows. A detector that raises is skipped:
explaining a failure must never turn a stored delivery into a server error.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass
from itertools import product
from urllib.parse import urlsplit, urlunsplit

from .providers import PROVIDERS, verify
from .signatures import VerificationResult

log = logging.getLogger("hookscope.diagnostics")


@dataclass(frozen=True)
class Diagnosis:
    cause: str  # a short stable identifier, e.g. "missing_signature"; safe to count in metrics
    message: str  # what went wrong, in one sentence
    fix: str  # what to change, in one sentence

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Delivery:
    """Everything a detector may look at. ``secret`` is never copied into a ``Diagnosis``."""

    source: str
    body: bytes
    headers: Mapping[str, str]
    secret: str | None
    url: str
    result: VerificationResult
    now: float | None = None

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((value for key, value in self.headers.items() if key.lower() == wanted), None)


Detector = Callable[[Delivery], "Diagnosis | None"]
DETECTORS: list[Detector] = []


def detector(function: Detector) -> Detector:
    """Register a detector. Order of definition is the order they run in."""
    DETECTORS.append(function)
    return function


def diagnose(delivery: Delivery) -> Diagnosis | None:
    """The most likely explanation for a rejected delivery, or ``None`` if it was not rejected."""
    if not delivery.result.rejected or delivery.source not in PROVIDERS:
        return None
    for run in DETECTORS:
        try:
            found = run(delivery)
        except Exception:  # noqa: BLE001 - see the module docstring
            log.exception("detector %s failed", run.__name__)
            continue
        if found is not None:
            return found
    return None


# ------------------------------------------------------------------------------ detectors
# General fallbacks go last; add specific detectors above them.


@detector
def wrong_provider(delivery: Delivery) -> Diagnosis | None:
    """The request carries another provider's headers: it was sent to the wrong ``/hooks/<source>``."""
    if delivery.result.status != "unsigned":
        return None
    for name, provider in PROVIDERS.items():
        if name == delivery.source:
            continue
        sent = {h.lower(): h for h in delivery.headers}
        # Most telling first: the signature header, then the event type and delivery id.
        present = next((sent[h] for h in provider.identifying_headers if h in sent), None)
        if present is None:
            continue
        base, found, _ = delivery.url.rpartition("/hooks/")
        corrected = f"{base}/hooks/{name}" if found else f"/hooks/{name}"
        return Diagnosis(
            "wrong_provider",
            f"This request looks like it came from {name} (it has the {present} header) but it was sent to "
            f"/hooks/{delivery.source}, which expects {PROVIDERS[delivery.source].signature_header}.",
            f"Point the {name} webhook at {corrected}, or if this is meant for {delivery.source} send it "
            f"with a {PROVIDERS[delivery.source].signature_header} header.",
        )
    return None


def duration(seconds: int) -> str:
    """``7425`` to ``"2 h 3 min 45 s"``; whole units only, largest first."""
    days, rest = divmod(abs(seconds), 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{n} {unit}" for n, unit in ((days, "d"), (hours, "h"), (minutes, "min"), (secs, "s")) if n]
    return " ".join(parts) or "0 s"


@detector
def timestamp_skew(delivery: Delivery) -> Diagnosis | None:
    """The timestamp is outside the window: say by how much, and whether it is old or in the future."""
    provider = PROVIDERS[delivery.source]
    if (
        delivery.result.status != "invalid"
        or not delivery.result.reason.startswith("timestamp outside tolerance")
        or provider.timestamp_from is None
    ):
        return None
    sent = provider.timestamp_from(delivery.headers)
    if sent is None:
        return None
    now = time.time() if delivery.now is None else delivery.now
    skew = int(now - sent)  # positive: the request is older than now
    window = f"{provider.timestamp_tolerance} seconds ({duration(provider.timestamp_tolerance)})"
    # Check the signature as of the moment it was sent, so the diagnosis can say whether only the
    # clock is at fault.
    at_send_time = (
        verify(delivery.source, delivery.body, delivery.headers, delivery.secret, delivery.url, now=sent)
        if delivery.secret
        else None
    )
    also = (
        ""
        if at_send_time is not None and at_send_time.status == "valid"
        else " The signature does not match even as of the moment it was sent, so there is a second "
        "problem (secret or body): fix the clock first, then check again."
    )
    if skew < 0:
        return Diagnosis(
            "clock_ahead",
            f"The timestamp is {-skew} seconds ({duration(skew)}) in the future; {delivery.source} only "
            f"accepts requests within {window} of now.{also}",
            "Check the clock on the machine running HookScope (`date -u`) and keep it synced with NTP: "
            f"it is behind {delivery.source}'s clock by about that much.",
        )
    return Diagnosis(
        "stale_timestamp",
        f"The timestamp is {skew} seconds ({duration(skew)}) old; {delivery.source} only accepts requests "
        f"within {window} of now.{also}",
        "If the clock on the machine running HookScope (`date -u`) is right, this is a replay or a very "
        f"late delivery: let {delivery.source} send a fresh one. If the clock is fast by about that much, "
        "fix it and keep it synced with NTP.",
    )


DEFAULT_PORTS = {"http": 80, "https": 443}


def _forwarded_url(seen: str, headers: Mapping[str, str]) -> str | None:
    """The URL a proxy in front of HookScope says the caller used, rebuilt from its headers."""
    lookup = {k.lower(): v for k, v in headers.items()}

    def first(name: str) -> str:
        return (lookup.get(name) or "").split(",")[0].strip()

    parts = urlsplit(seen)
    scheme = first("x-forwarded-proto") or parts.scheme
    host = first("x-forwarded-host") or first("host") or parts.netloc
    port = first("x-forwarded-port")
    if port.isdigit() and ":" not in host and int(port) != DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parts.path, parts.query, ""))


def _toggle_port(scheme: str, netloc: str) -> str | None:
    """Add the scheme's default port to a host, or take it off; None when neither applies."""
    default = DEFAULT_PORTS.get(scheme)
    if netloc.startswith("[") or default is None:
        return None
    host, sep, number = netloc.rpartition(":")
    if sep and number == str(default):
        return host
    return None if sep else f"{netloc}:{default}"


def _reorder(query: str, how: str) -> str | None:
    """The query parameters sorted or reversed; None when there is nothing to reorder."""
    tokens = query.split("&")
    if len(tokens) < 2:
        return None
    return "&".join(sorted(tokens) if how == "sorted" else reversed(tokens))


def url_variants(seen: str, headers: Mapping[str, str]) -> Iterator[tuple[str, str]]:
    """URLs the provider might have signed, as (url, what differs from ``seen``), fewest changes first.

    Starts from the URL HookScope saw and from the one a proxy's forwarding headers describe, then
    tries the scheme swapped, a trailing slash added or removed, the default port shown or hidden, and
    the query parameters in another order.
    """
    bases = [seen]
    forwarded = _forwarded_url(seen, headers)
    if forwarded and forwarded != seen:
        bases.append(forwarded)
    found: dict[str, list[str]] = {}
    orders = ("as sent", "sorted", "reversed")
    for base, swap, slash, port, order in product(bases, (0, 1), (0, 1), (0, 1), orders):
        parts = urlsplit(base)
        scheme, netloc, path, query = parts.scheme, parts.netloc, parts.path, parts.query
        if swap:
            scheme = "https" if scheme == "http" else "http"
        if slash:
            path = path[:-1] if path.endswith("/") and len(path) > 1 else path + "/"
        if port:
            netloc = _toggle_port(scheme, netloc)
        if order != "as sent":
            query = _reorder(query, order)
        if netloc is None or query is None:
            continue
        candidate = urlunsplit((scheme, netloc, path, query, ""))
        if candidate != seen and candidate not in found:
            found[candidate] = describe_url_change(seen, candidate)
    for candidate, changes in sorted(found.items(), key=lambda item: len(item[1])):
        yield candidate, "; ".join(changes)


def describe_url_change(seen: str, signed: str) -> list[str]:
    """What differs between two URLs, in words (scheme, host, port, path, query order)."""
    a, b = urlsplit(seen), urlsplit(signed)
    changes = []
    if a.scheme != b.scheme:
        changes.append(f"the scheme is {b.scheme}, not {a.scheme}")
    if a.hostname != b.hostname:
        changes.append(f"the host is {b.hostname}, not {a.hostname}")
    if (a.port, b.port) != (None, None) and a.port != b.port:
        changes.append(f"the port is {b.port or 'the default'}, not {a.port or 'the default'}")
    if a.path != b.path:
        slashed = b.path == a.path + "/"
        changes.append("the path has a trailing slash" if slashed else "the path has no trailing slash")
    if a.query != b.query:
        changes.append("the query parameters are in a different order")
    return changes


@detector
def url_mismatch(delivery: Delivery) -> Diagnosis | None:
    """A provider that signs the URL (Twilio): the signature fits a slightly different URL than seen."""
    provider = PROVIDERS[delivery.source]
    if delivery.result.status != "invalid" or not provider.url_signed or not delivery.secret:
        return None
    for candidate, what in url_variants(delivery.url, delivery.headers):
        again = verify(delivery.source, delivery.body, delivery.headers, delivery.secret, candidate)
        if again.status == "valid":
            return Diagnosis(
                "url_mismatch",
                f"{delivery.source} signed {candidate}, but HookScope saw {delivery.url} ({what}). The "
                f"signature covers the exact URL {delivery.source} calls, so any difference breaks it.",
                f"Make the URL HookScope sees identical to {candidate}: configure the same URL in "
                f"{delivery.source}, and if a proxy is in front of HookScope have it pass the original "
                "Host header and X-Forwarded-Proto (the Docker image already trusts X-Forwarded-Proto).",
            )
    return None


def secret_variants(secret: str) -> Iterator[tuple[str, str, str]]:
    """Cleaned-up versions of a secret, as (cause, what was wrong, secret).

    Secrets pasted into an env file or a dashboard often pick up a trailing newline, a space, or a pair
    of quotes that a shell or a runtime kept literally.
    """
    seen = {secret}

    def offer(cause: str, what: str, candidate: str) -> Iterator[tuple[str, str, str]]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield cause, what, candidate

    yield from offer("secret_whitespace", "a trailing newline", secret.rstrip("\r\n"))
    yield from offer("secret_whitespace", "leading or trailing whitespace", secret.strip())
    for mark, name in (('"', "double"), ("'", "single")):
        for base in (secret, secret.strip()):
            if len(base) >= 2 and base[0] == base[-1] == mark:
                what = f"surrounding {name} quotes" + (" and whitespace" if base is not secret else "")
                yield from offer("secret_quotes", what, base[1:-1])
                yield from offer("secret_quotes", what, base[1:-1].strip())


@detector
def secret_has_stray_characters(delivery: Delivery) -> Diagnosis | None:
    """The signature fits the secret once whitespace or quotes are taken off the configured value."""
    if delivery.result.status != "invalid" or not delivery.secret:
        return None
    variable = f"HOOKSCOPE_SECRET_{delivery.source.upper()}"
    for cause, what, candidate in secret_variants(delivery.secret):
        again = verify(
            delivery.source, delivery.body, delivery.headers, candidate, url=delivery.url, now=delivery.now
        )
        if again.status == "valid":
            return Diagnosis(
                cause,
                f"The signature is valid if {variable} has {what} removed, so the secret HookScope "
                "is using is not exactly the one the provider signs with.",
                f"Set {variable} to the bare secret: no spaces, no newline and no quotes around it. In "
                "an env file or a compose file, check whether your runtime keeps quotes literally.",
            )
    return None


# Re-verifying variants of a big body is cheap, but there is no reason to do it for megabytes.
MAX_VARIANT_BYTES = 256 * 1024
BOM = b"\xef\xbb\xbf"


def body_variants(body: bytes) -> Iterator[tuple[str, bytes]]:
    """Ways the signed body might have looked before something changed it, as (description, bytes).

    Each variant undoes one common change: re-serialised JSON (spacing, key order, escaping), a
    trailing newline added or removed, CRLF line endings, a byte order mark, stray surrounding space.
    """
    if body.endswith(b"\n"):
        yield "the body without its trailing newline", body.rstrip(b"\r\n")
    else:
        yield "the body with a trailing newline added", body + b"\n"
    if body.startswith(BOM):
        yield "the body without its byte order mark (BOM)", body[len(BOM) :]
    else:
        yield "the body with a byte order mark (BOM) added", BOM + body
    if b"\r\n" in body:
        yield "the body with LF line endings instead of CRLF", body.replace(b"\r\n", b"\n")
    elif b"\n" in body.rstrip(b"\n"):
        yield "the body with CRLF line endings instead of LF", body.replace(b"\n", b"\r\n")
    if body != body.strip():
        yield "the body without surrounding whitespace", body.strip()
    # Re-serialised JSON: spacing, key order, escaping, a final newline. Last, since it is the vaguest.
    try:
        document = json.loads(body.decode("utf-8-sig"))
    except ValueError:
        document = None
    if document is not None:
        forms = {
            "compact JSON": dict(separators=(",", ":"), ensure_ascii=False),
            "compact JSON with non-ASCII escaped": dict(separators=(",", ":")),
            "JSON with the default spacing": dict(ensure_ascii=False),
            "JSON with the default spacing and non-ASCII escaped": {},
            "pretty-printed JSON (2 spaces)": dict(indent=2, ensure_ascii=False),
            "pretty-printed JSON (4 spaces)": dict(indent=4, ensure_ascii=False),
            "JSON with sorted keys": dict(separators=(",", ":"), ensure_ascii=False, sort_keys=True),
        }
        for label, options in forms.items():
            text = json.dumps(document, **options).encode()
            yield f"the body as {label}", text
            yield f"the body as {label} plus a final newline", text + b"\n"


@detector
def body_changed_in_transit(delivery: Delivery) -> Diagnosis | None:
    """The signature fits a slightly different body: something re-encoded it on the way here."""
    if delivery.result.status != "invalid" or not delivery.secret or len(delivery.body) > MAX_VARIANT_BYTES:
        return None
    for what, variant in body_variants(delivery.body):
        if variant == delivery.body:
            continue
        again = verify(
            delivery.source, variant, delivery.headers, delivery.secret, url=delivery.url, now=delivery.now
        )
        if again.status == "valid":
            return Diagnosis(
                "body_reencoded",
                f"The signature is valid for {what}, not for the body that arrived, so the request body "
                f"was changed between {delivery.source} and HookScope.",
                "Make HookScope receive the exact bytes that were sent: turn off anything in front of it "
                "that parses and re-serialises the body (a proxy, an API gateway, a framework's JSON "
                "middleware), or forward the raw body untouched.",
            )
    return None


@detector
def missing_signature(delivery: Delivery) -> Diagnosis | None:
    if delivery.result.status != "unsigned":
        return None
    header = PROVIDERS[delivery.source].signature_header or "signature"
    return Diagnosis(
        "missing_signature",
        f"The request has no {header} header, so there is nothing to check.",
        f"Send the request from {delivery.source}, or if a proxy sits in front of HookScope make sure it "
        f"passes the {header} header through.",
    )


@detector
def unexplained_mismatch(delivery: Delivery) -> Diagnosis | None:
    """The catch-all: a signature was sent and did not match, and no specific cause was recognised."""
    if delivery.result.status != "invalid":
        return None
    provider = PROVIDERS[delivery.source]
    secret_variable = f"HOOKSCOPE_SECRET_{delivery.source.upper()}"
    return Diagnosis(
        "unexplained",
        f"The {provider.signature_header or 'signature'} header does not match what HookScope computed "
        f"({delivery.result.reason or 'invalid'}).",
        f"Check that {secret_variable} is exactly the signing secret from the {delivery.source} "
        "dashboard (no spaces or quotes), and that nothing between the provider and HookScope changes "
        "the request body.",
    )
