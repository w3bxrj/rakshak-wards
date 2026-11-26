"""Security primitives: secret validation, domain-separated HMAC derivations, and resource metrics."""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
from pathlib import Path
from typing import Any

import yaml

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 without I, L, O, U


class SecretMissingError(RuntimeError):
    """Raised when RAKSHA_SECRET is missing or empty."""


def require_secret() -> bytes:
    """Read and validate RAKSHA_SECRET from the environment without logging it."""
    raw = os.environ.get("RAKSHA_SECRET", "")
    if not raw or not raw.strip():
        raise SecretMissingError("RAKSHA_SECRET is missing or empty")
    return raw.encode("utf-8")


def load_policy(path: Path) -> dict[str, Any]:
    """Load YAML policy configuration with safe defaults."""
    defaults: dict[str, Any] = {
        "age_band_years": 5,
        "date_shift_max_days": 180,
        "max_json_depth": 64,
        "max_base64_attach_len": 24,
    }
    if not path.is_file():
        return defaults
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(loaded, dict):
        defaults.update(loaded)
    return defaults


def derive_pseudonym(patient_key: str, secret: bytes) -> str:
    """Derive a stable, non-reversible PSN-XXXXXX pseudonym using HMAC-SHA256."""
    if not secret:
        raise SecretMissingError("secret must be non-empty")
    digest = hmac.new(secret, b"psn|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:5], "big")
    code = "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))
    return f"PSN-{code}"


def derive_date_shift_days(patient_key: str, secret: bytes, max_days: int = 180) -> int:
    """Derive a deterministic non-zero per-patient day offset in [-max_days, +max_days]."""
    if not secret:
        raise SecretMissingError("secret must be non-empty")
    if max_days < 1:
        raise ValueError("max_days must be >= 1")
    digest = hmac.new(secret, b"shift|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    val = int.from_bytes(digest[:4], "big") % (2 * max_days) - max_days
    return val if val != 0 else 1


def derive_record_date_shift_days(record_id: str, secret: bytes, max_days: int = 180) -> int:
    """Derive a record-scoped day offset from a separate HMAC domain for unlinked records."""
    if not secret:
        raise SecretMissingError("secret must be non-empty")
    if max_days < 1:
        raise ValueError("max_days must be >= 1")
    digest = hmac.new(secret, b"recshift|" + record_id.encode("utf-8"), hashlib.sha256).digest()
    val = int.from_bytes(digest[:4], "big") % (2 * max_days) - max_days
    return val if val != 0 else 1


def peak_rss_mb() -> float | None:
    """Measure process peak RSS in MB where supported; return None if unavailable."""
    try:
        import resource  # POSIX only

        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024.0 if sys.platform != "darwin" else r / 1048576.0, 2)
    except Exception:
        pass
    try:
        import psutil

        rss = psutil.Process(os.getpid()).memory_info().rss
        return round(rss / (1024.0 * 1024.0), 2)
    except Exception:
        return None
