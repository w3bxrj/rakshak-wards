"""Unified Phase 3 sanitization interface across all channels."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from rakshak.attachments import strip_opaque_attachments_text
from rakshak.detect import (
    AliasIndex,
    classify_field_name,
    redact_free_text,
    redact_structured_value,
)

# Generic schema/JSON keys that must never be treated as PII keys
_SCHEMA_KEYS = {
    "resourcetype", "id", "meta", "metadata", "source", "source_path", "entry", "fullurl",
    "resource", "reference", "type", "text", "div", "status", "identifier", "system", "value",
    "name", "given", "family", "telecom", "address", "line", "city", "district", "state",
    "postalcode", "birthdate", "gender", "patient", "patients", "visits", "results", "panels",
    "wards", "tickets", "records", "data", "content", "attachment", "contenttype", "title",
    "url", "filename", "description", "code", "coding", "display", "unit", "result",
    "subject", "encounter", "period", "start", "end", "note", "notes", "diagnosis",
}

_PATH_PII_SEG_RE = re.compile(
    r"(?<=[\\/])([A-Z][a-z]+(?:_[A-Z][a-z]+)+_\d{4,8}|[A-Z][a-z]+_[A-Z][a-z]+)(?=[\\/]|$)"
)
_FILENAME_NAME_RE = re.compile(r"(?<![A-Za-z])([A-Z][a-z]+[_-][A-Z][a-z]+(?:[_-]\d{4,8})?)(?![A-Za-z])")
_FILENAME_MRN_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z]{2,6}[_-]\d{2,4}[_-][A-Za-z0-9_-]{3,12}|[A-Za-z]{2,6}[_-](?!20[12]\d(?![0-9]))\d{4,10}|[A-Za-z]{2,6}\d{5,10}|\d{5,8})(?![A-Za-z0-9])")


@dataclass
class SanitizationStats:
    """Aggregate counts collected without storing any PII."""

    identifiers_detected: int = 0
    attachments_removed: int = 0


@dataclass
class Sanitizer:
    """Single entry point where Phase 3 detection hooks into every channel."""

    stats: SanitizationStats = field(default_factory=SanitizationStats)
    alias_index: AliasIndex | None = None

    def sanitize_text(self, text: str, channel: str = "content") -> str:
        """Sanitize free text, metadata, or narratives while stripping opaque base64."""
        if not text:
            return text
        cleaned, n_att = strip_opaque_attachments_text(text)
        self.stats.attachments_removed += n_att
        self.stats.identifiers_detected += n_att
        full_only = channel in {"filename", "dirname", "header", "key"}
        cleaned, n_det = redact_free_text(cleaned, alias_index=self.alias_index, full_aliases_only=full_only)
        self.stats.identifiers_detected += n_det
        return cleaned

    def sanitize_structured(self, field_name: str, value: str) -> str:
        """Sanitize a CSV cell or JSON scalar using column/key context + free-text fallback."""
        if not value:
            return value
        cleaned, n_att = strip_opaque_attachments_text(value)
        self.stats.attachments_removed += n_att
        self.stats.identifiers_detected += n_att
        cleaned, n_det = redact_structured_value(field_name, cleaned, alias_index=self.alias_index)
        self.stats.identifiers_detected += n_det
        return cleaned

    def sanitize_header(self, header: str) -> str:
        """Sanitize CSV/TSV column headers only when they contain PII (not schema names)."""
        if header.strip().casefold() in _SCHEMA_KEYS:
            return header
        cleaned = self.sanitize_text(header, channel="header")
        cleaned, n1 = _FILENAME_MRN_RE.subn("[MRN]", cleaned)
        cleaned, n2 = _FILENAME_NAME_RE.subn("[PATIENT_NAME]", cleaned)
        self.stats.identifiers_detected += n1 + n2
        if classify_field_name(header) is None and cleaned == header:
            _CLIN_HDR_WORDS = {
                "date", "time", "ward", "test", "unit", "code", "type", "name", "age", "sex",
                "gender", "note", "notes", "rate", "level", "status", "result", "count",
                "total", "amount", "claim", "bill", "days", "visit", "hospital", "doctor",
                "blood", "pressure", "pulse", "temp", "sugar", "diagnosis", "admission", "discharge",
            }
            def _hdr_repl(m: re.Match[str]) -> str:
                w1, w2 = m.group(1).split()
                if w1.casefold() in _CLIN_HDR_WORDS or w2.casefold() in _CLIN_HDR_WORDS:
                    return m.group(0)
                self.stats.identifiers_detected += 1
                return "[PATIENT_NAME]"
            cleaned = re.sub(r"\b([A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20})\b", _hdr_repl, cleaned)
        return cleaned

    def sanitize_key(self, key: str) -> str:
        """Sanitize JSON object keys that contain PII while preserving schema keys."""
        if key.strip().casefold() in _SCHEMA_KEYS or classify_field_name(key) is not None:
            return key
        cleaned = self.sanitize_text(key, channel="key")
        if cleaned == key and re.match(r"^[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}$", key.strip()):
            self.stats.identifiers_detected += 1
            return "[PATIENT_NAME]"
        return cleaned

    def sanitize_metadata(self, value: str) -> str:
        """Sanitize metadata string fields including embedded export file paths and titles."""
        if not value:
            return value
        cleaned, n_path = _PATH_PII_SEG_RE.subn("[PATIENT_NAME]", value)
        cleaned, n1 = _FILENAME_MRN_RE.subn("[MRN]", cleaned)
        cleaned, n2 = _FILENAME_NAME_RE.subn("[PATIENT_NAME]", cleaned)
        self.stats.identifiers_detected += n_path + n1 + n2
        return self.sanitize_text(cleaned, channel="metadata")

    def sanitize_fhir_narrative(self, div_html: str) -> str:
        """Sanitize FHIR narrative HTML/text."""
        return self.sanitize_text(div_html, channel="fhir_narrative")

    def sanitize_rel_path(self, rel_path: str) -> str:
        """Sanitize directory and file name components while preserving extension."""
        parts = rel_path.split("/")
        out_parts: list[str] = []
        for idx, part in enumerate(parts):
            is_file = idx == len(parts) - 1 and "." in part
            if is_file:
                stem, ext = part.rsplit(".", 1)
                clean_stem = self.sanitize_text(stem, channel="filename")
                clean_stem, n1 = _FILENAME_MRN_RE.subn("[MRN]", clean_stem)
                clean_stem, n2 = _FILENAME_NAME_RE.subn("[PATIENT_NAME]", clean_stem)
                self.stats.identifiers_detected += n1 + n2
                clean_stem = re.sub(r'[<>:"/\\|?*]', "_", clean_stem).strip() or "redacted_file"
                out_parts.append(f"{clean_stem}.{ext}")
            else:
                clean_dir = self.sanitize_text(part, channel="dirname")
                clean_dir, n1 = _FILENAME_MRN_RE.subn("[MRN]", clean_dir)
                clean_dir, n2 = _FILENAME_NAME_RE.subn("[PATIENT_NAME]", clean_dir)
                self.stats.identifiers_detected += n1 + n2
                clean_dir = re.sub(r'[<>:"/\\|?*]', "_", clean_dir).strip() or "redacted_dir"
                out_parts.append(clean_dir)
        return "/".join(out_parts)
