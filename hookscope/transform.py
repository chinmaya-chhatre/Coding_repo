"""Payload transforms: map a provider payload onto your own schema.

A forwarding rule can carry a ``transform`` mapping. Each output key is either a
JSONPath expression evaluated against the event's JSON body, an ``@`` reference to
event metadata, or a nested mapping (for nested output objects)::

    {
      "repo": "$.repository.full_name",
      "author": "$.sender.login",
      "first_commit": "$.commits[0].message",
      "commit_ids": "$.commits[*].id",
      "meta": {"source": "@source", "type": "@event_type", "id": "@event_id"}
    }

Supported JSONPath subset: ``$`` (the whole body), ``.key``, ``['key']`` /
``["key"]``, ``[n]`` (negative indexes count from the end), ``[*]`` and ``.*``
(every element or value), and recursive descent ``..`` (``$..id``, ``$..[0]``,
``$..*``), which applies the next selector to a node and all of its descendants.
A path with a wildcard or recursive descent yields a list of all matches (outer
nodes before the ones nested inside them); any other path yields a single value, or ``null`` when nothing
matches.
"""

from __future__ import annotations

import json
import re

WILDCARD = object()
DESCENT = object()
META_FIELDS = ("source", "event_type", "event_id", "received_at", "verification")
MAX_DEPTH = 5

_NAME = re.compile(r"[A-Za-z0-9_\-]+")
_INDEX = re.compile(r"-?\d+")


class InvalidTransformError(ValueError):
    pass


def compile_path(expr: str) -> tuple:
    """Parse a JSONPath expression into segments.

    Segments are ``str`` keys, ``int`` indexes, ``WILDCARD``, and ``DESCENT`` (always
    followed by the selector it applies to).
    """
    if not expr.startswith("$"):
        raise InvalidTransformError(f"path '{expr}' must start with '$'")
    segments: list = []
    pos = 1
    while pos < len(expr):
        char = expr[pos]
        if char == ".":
            start = pos + 1
            if expr.startswith(".", start):
                segments.append(DESCENT)
                start += 1
                if expr.startswith("[", start):
                    pos = start
                    continue
            if expr.startswith("*", start):
                segments.append(WILDCARD)
                pos = start + 1
                continue
            match = _NAME.match(expr, start)
            if not match:
                raise InvalidTransformError(f"path '{expr}': expected a key name at position {start}")
            segments.append(match.group())
            pos = match.end()
        elif char == "[":
            end = expr.find("]", pos)
            if end == -1:
                raise InvalidTransformError(f"path '{expr}': unclosed '['")
            inner = expr[pos + 1 : end]
            if inner == "*":
                segments.append(WILDCARD)
            elif _INDEX.fullmatch(inner):
                segments.append(int(inner))
            elif len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in "'\"":
                segments.append(inner[1:-1])
            else:
                raise InvalidTransformError(f"path '{expr}': unsupported selector '[{inner}]'")
            pos = end + 1
        else:
            raise InvalidTransformError(f"path '{expr}': unexpected '{char}' at position {pos}")
    return tuple(segments)


def resolve(payload: object, segments: tuple) -> object:
    """Evaluate compiled segments; wildcard and descent paths return a list of every match."""
    nodes = [payload]
    for segment in segments:
        if segment is DESCENT:
            nodes = [descendant for node in nodes for descendant in _self_and_descendants(node)]
            continue
        found = []
        for node in nodes:
            if segment is WILDCARD:
                if isinstance(node, list):
                    found.extend(node)
                elif isinstance(node, dict):
                    found.extend(node.values())
            elif isinstance(segment, int):
                if isinstance(node, list) and -len(node) <= segment < len(node):
                    found.append(node[segment])
            elif isinstance(node, dict) and segment in node:
                found.append(node[segment])
        nodes = found
    if WILDCARD in segments or DESCENT in segments:
        return nodes
    return nodes[0] if nodes else None


def _self_and_descendants(node: object) -> list:
    """``node`` followed by every value nested inside it, in document (pre-)order."""
    ordered = []
    stack = [node]
    while stack:
        current = stack.pop()
        ordered.append(current)
        if isinstance(current, dict):
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))
    return ordered


def validate_mapping(mapping: object, depth: int = 0) -> None:
    """Raise ``InvalidTransformError`` unless ``mapping`` is a usable transform."""
    if not isinstance(mapping, dict) or not mapping:
        raise InvalidTransformError("transform must be a non-empty object")
    if depth >= MAX_DEPTH:
        raise InvalidTransformError(f"transform is nested more than {MAX_DEPTH} levels deep")
    for key, spec in mapping.items():
        if isinstance(spec, dict):
            validate_mapping(spec, depth + 1)
        elif isinstance(spec, str) and spec.startswith("@"):
            if spec[1:] not in META_FIELDS:
                raise InvalidTransformError(
                    f"transform key '{key}': unknown reference '{spec}'. Supported: "
                    + ", ".join(f"@{name}" for name in META_FIELDS)
                )
        elif isinstance(spec, str):
            compile_path(spec)
        else:
            raise InvalidTransformError(f"transform key '{key}' must be a path string or an object")


def apply_transform(mapping: dict, event: dict, event_type: str | None) -> dict:
    """Build the output document for ``event``; a non-JSON body behaves like an empty one."""
    try:
        payload = json.loads(event["body"])
    except ValueError:
        payload = None
    meta = {
        "source": event["source"],
        "event_type": event_type,
        "event_id": event["id"],
        "received_at": event["received_at"],
        "verification": event["verification"],
    }
    return _build(mapping, payload, meta)


def _build(mapping: dict, payload: object, meta: dict) -> dict:
    output = {}
    for key, spec in mapping.items():
        if isinstance(spec, dict):
            output[key] = _build(spec, payload, meta)
        elif spec.startswith("@"):
            output[key] = meta[spec[1:]]
        else:
            output[key] = resolve(payload, compile_path(spec))
    return output
