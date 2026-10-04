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
``$..*``), which applies the next selector to a node and all of its descendants,
and filters ``[?(...)]`` (see ``Filter``), which keep the elements of a list (or
the values of an object) that satisfy a condition, e.g.
``$.commits[?(@.author.name == 'octocat')].id``.
A path with a wildcard, recursive descent or filter yields a list of all matches
(outer nodes before the ones nested inside them); any other path yields a single
value, or ``null`` when nothing matches.
"""

from __future__ import annotations

import json
import operator
import re
from dataclasses import dataclass, field

WILDCARD = object()
DESCENT = object()
META_FIELDS = ("source", "event_type", "event_id", "received_at", "verification")
MAX_DEPTH = 5

_NAME = re.compile(r"[A-Za-z0-9_\-]+")
_INDEX = re.compile(r"-?\d+")


class InvalidTransformError(ValueError):
    pass


MISSING = object()

_FILTER_TOKEN = re.compile(
    r"""\s*(?:
        (?P<path>@(?:\.[A-Za-z0-9_\-]+|\[(?:-?\d+|'[^']*'|"[^"]*")\])*)
      | (?P<string>'[^']*'|"[^"]*")
      | (?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
      | (?P<word>true|false|null)\b
      | (?P<op>==|!=|<=|>=|<|>|&&|\|\||!|\(|\))
    )""",
    re.VERBOSE,
)
_ORDERING = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge}
_COMPARISONS = ("==", "!=", *_ORDERING)
_WORDS = {"true": True, "false": False, "null": None}


@dataclass(frozen=True)
class Filter:
    """A ``[?(...)]`` selector: keeps the list elements / object values it holds for.

    The condition compares relative paths (``@`` is the candidate element, followed by
    ``.key``, ``['key']`` or ``[n]``) with each other or with JSON literals (strings,
    numbers, ``true``, ``false``, ``null``) using ``==``, ``!=``, ``<``, ``<=``, ``>``,
    ``>=``. A bare path tests that the field exists. Conditions combine with ``&&``,
    ``||``, ``!`` and parentheses. A missing field equals nothing (so ``!=`` holds for
    it) and fails every ordering comparison; ``<`` and friends only compare two numbers
    or two strings.
    """

    expr: str
    tree: tuple = field(compare=False, repr=False)

    @classmethod
    def parse(cls, expr: str) -> Filter:
        tokens = _tokenize_filter(expr)
        tree, pos = _parse_or(tokens, 0)
        if pos != len(tokens):
            raise InvalidTransformError(f"unexpected '{tokens[pos][1]}'")
        return cls(expr, tree)

    def __call__(self, node: object) -> bool:
        return _evaluate(self.tree, node)


def _tokenize_filter(expr: str) -> list[tuple[str, str]]:
    tokens = []
    pos = 0
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        match = _FILTER_TOKEN.match(expr, pos)
        if not match or match.end() == pos:
            raise InvalidTransformError(f"unexpected '{expr[pos:].strip()[0]}'")
        tokens.append((match.lastgroup, match.group(match.lastgroup)))
        pos = match.end()
    if not tokens:
        raise InvalidTransformError("empty condition")
    return tokens


def _parse_or(tokens: list, pos: int) -> tuple[tuple, int]:
    left, pos = _parse_and(tokens, pos)
    while pos < len(tokens) and tokens[pos] == ("op", "||"):
        right, pos = _parse_and(tokens, pos + 1)
        left = ("or", left, right)
    return left, pos


def _parse_and(tokens: list, pos: int) -> tuple[tuple, int]:
    left, pos = _parse_unary(tokens, pos)
    while pos < len(tokens) and tokens[pos] == ("op", "&&"):
        right, pos = _parse_unary(tokens, pos + 1)
        left = ("and", left, right)
    return left, pos


def _parse_unary(tokens: list, pos: int) -> tuple[tuple, int]:
    if pos >= len(tokens):
        raise InvalidTransformError("condition ends unexpectedly")
    if tokens[pos] == ("op", "!"):
        inner, pos = _parse_unary(tokens, pos + 1)
        return ("not", inner), pos
    if tokens[pos] == ("op", "("):
        inner, pos = _parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ("op", ")"):
            raise InvalidTransformError("missing ')'")
        return inner, pos + 1
    left, pos = _parse_operand(tokens, pos)
    if pos < len(tokens) and tokens[pos][0] == "op" and tokens[pos][1] in _COMPARISONS:
        op = tokens[pos][1]
        right, pos = _parse_operand(tokens, pos + 1)
        return ("cmp", op, left, right), pos
    if left[0] != "path":
        raise InvalidTransformError("a literal on its own is not a condition; compare it with a path")
    return ("exists", left), pos


def _parse_operand(tokens: list, pos: int) -> tuple[tuple, int]:
    if pos >= len(tokens):
        raise InvalidTransformError("condition ends unexpectedly")
    kind, text = tokens[pos]
    if kind == "path":
        return ("path", compile_path("$" + text[1:])), pos + 1
    if kind == "string":
        return ("value", text[1:-1]), pos + 1
    if kind == "number":
        value = float(text) if any(c in text for c in ".eE") else int(text)
        return ("value", value), pos + 1
    if kind == "word":
        return ("value", _WORDS[text]), pos + 1
    raise InvalidTransformError(f"expected a path or a value, got '{text}'")


def _evaluate(tree: tuple, node: object) -> bool:
    kind = tree[0]
    if kind == "or":
        return _evaluate(tree[1], node) or _evaluate(tree[2], node)
    if kind == "and":
        return _evaluate(tree[1], node) and _evaluate(tree[2], node)
    if kind == "not":
        return not _evaluate(tree[1], node)
    if kind == "exists":
        return _operand(tree[1], node) is not MISSING
    _, op, left, right = tree
    a, b = _operand(left, node), _operand(right, node)
    if op == "==":
        return _equal(a, b)
    if op == "!=":
        return not _equal(a, b)
    comparable = (_is_number(a) and _is_number(b)) or (isinstance(a, str) and isinstance(b, str))
    return comparable and _ORDERING[op](a, b)


def _operand(operand: tuple, node: object) -> object:
    if operand[0] == "value":
        return operand[1]
    current = node
    for segment in operand[1]:
        if isinstance(segment, int):
            if not (isinstance(current, list) and -len(current) <= segment < len(current)):
                return MISSING
        elif not (isinstance(current, dict) and segment in current):
            return MISSING
        current = current[segment]
    return current


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _equal(a: object, b: object) -> bool:
    if a is MISSING or b is MISSING:
        return a is b
    if _is_number(a) and _is_number(b):
        return a == b
    # Keep JSON types apart: true is not 1, "1" is not 1.
    return type(a) is type(b) and a == b


def compile_path(expr: str) -> tuple:
    """Parse a JSONPath expression into segments.

    Segments are ``str`` keys, ``int`` indexes, ``WILDCARD``, ``Filter`` selectors, and
    ``DESCENT`` (always followed by the selector it applies to).
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
        elif expr.startswith("[?", pos):
            end = _filter_end(expr, pos + 2)
            inner = expr[pos + 2 : end]
            try:
                segments.append(Filter.parse(inner))
            except InvalidTransformError as exc:
                raise InvalidTransformError(f"path '{expr}': invalid filter '[?{inner}]': {exc}") from None
            pos = end + 1
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


def _filter_end(expr: str, pos: int) -> int:
    """Index of the ``]`` closing a filter that starts at ``pos``, skipping quoted text."""
    depth = 0
    quote = None
    for index in range(pos, len(expr)):
        char = expr[index]
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            if depth == 0:
                return index
            depth -= 1
    raise InvalidTransformError(f"path '{expr}': unclosed '['")


def resolve(payload: object, segments: tuple) -> object:
    """Evaluate compiled segments; wildcard, descent and filter paths return a list of every match."""
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
            elif isinstance(segment, Filter):
                children = node if isinstance(node, list) else node.values() if isinstance(node, dict) else ()
                found.extend(child for child in children if segment(child))
            elif isinstance(segment, int):
                if isinstance(node, list) and -len(node) <= segment < len(node):
                    found.append(node[segment])
            elif isinstance(node, dict) and segment in node:
                found.append(node[segment])
        nodes = found
    if any(segment is WILDCARD or segment is DESCENT or isinstance(segment, Filter) for segment in segments):
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
