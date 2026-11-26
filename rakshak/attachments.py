"""Embedded and opaque attachment handling."""
from __future__ import annotations

import base64
import binascii
import re

_DATA_URI_RE = re.compile(r"data:[^;\s\"']+;base64,[A-Za-z0-9+/=]{16,}")
_B64_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def is_valid_b64_payload(token: str) -> bool:
    """Return True if token is a valid base64-encoded payload (not a normal word/ID)."""
    if len(token) < 24 or any(ch.isspace() for ch in token):
        return False
    has_upper = any("A" <= c <= "Z" for c in token)
    has_lower = any("a" <= c <= "z" for c in token)
    if not (has_upper and has_lower):
        return False
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    # Accept if it has digits/symbols or decodes to text with spaces/punctuation or binary
    if any(c.isdigit() or c in "+/=" for c in token):
        return True
    try:
        decoded = raw.decode("utf-8")
        return any(ch in decoded for ch in (" ", "\n", ":", "{", "<"))
    except UnicodeDecodeError:
        return True


def looks_like_encoded_attachment(value: object) -> bool:
    """True only when a value is an actual encoded attachment string, not structured clinical data."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if _DATA_URI_RE.match(s):
        return True
    if len(s) >= 16 and not any(ch.isspace() for ch in s):
        padded = s + "=" * (-len(s) % 4)
        try:
            base64.b64decode(padded, validate=True)
            return True
        except (binascii.Error, ValueError):
            return False
    return False


def strip_opaque_attachments_text(text: str) -> tuple[str, int]:
    """Remove data-URI base64 and long opaque base64 runs from free text."""
    removed = 0
    text, n1 = _DATA_URI_RE.subn("[ATTACHMENT_REMOVED]", text)
    removed += n1

    def _repl(match: re.Match[str]) -> str:
        nonlocal removed
        tok = match.group(0)
        if is_valid_b64_payload(tok):
            removed += 1
            return "[ATTACHMENT_REMOVED]"
        return tok

    text = _B64_RUN_RE.sub(_repl, text)
    return text, removed


def decode_b64_json(value: str, max_bytes: int = 1_000_000, max_depth: int = 64) -> tuple[bool, object]:
    """Bounded base64 decode; return (True, parsed_json) if valid UTF-8 JSON within bounds, else (False, None)."""
    import json

    s = value.strip()
    if len(s) > max_bytes * 2:
        return False, None
    m = _DATA_URI_RE.match(s)
    b64_part = s.split(",", 1)[1] if m else s
    padded = b64_part + "=" * (-len(b64_part) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False, None
    if len(raw) > max_bytes:
        return False, None
    try:
        text = raw.decode("utf-8", errors="strict")
        obj = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False, None
    # Bounded nesting check
    stack: list[tuple[object, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            return False, None
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node if isinstance(v, (dict, list)))
    return True, obj


def is_attachment_key(key: str) -> bool:
    """Identify JSON/FHIR keys that may carry opaque attachment payloads."""
    low = key.strip().casefold()
    return low in {
        "data", "attachment_data", "base64", "file_bytes", "raw_payload",
        "payload", "scan_b64", "scan", "scanned_form", "raw_b64", "encoded",
    }
