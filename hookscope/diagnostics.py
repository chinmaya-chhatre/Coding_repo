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
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass

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
