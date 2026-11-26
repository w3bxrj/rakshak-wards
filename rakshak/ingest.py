"""Resilient multi-format ingestion, validation, and format-preserving writers."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from rakshak.attachments import decode_b64_json, is_attachment_key, looks_like_encoded_attachment
from rakshak.detect import classify_field_name
from rakshak.sanitize import Sanitizer

SUPPORTED_EXTENSIONS = {".csv", ".tsv", ".json", ".txt"}

_PATIENT_ARRAY_KEYS = {"patients", "visits", "results", "records", "encounters", "claims", "admissions"}
_AGGREGATE_ARRAY_KEYS = {"wards", "panels", "tickets", "items", "entries", "reference_ranges"}
_PATIENT_ITEM_HINTS = {
    "patient", "patient_name", "name", "uhid", "mrn", "phone", "mobile", "dob", "age", "aadhaar", "abha",
    "rx", "dose", "dose_mg", "diagnosis", "vitals", "note",
}


class QuarantineError(ValueError):
    """Raised with a fixed, PII-free reason code when a file must be quarantined."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def decode_bytes(raw: bytes) -> str:
    """Decode UTF-8-BOM, UTF-16, UTF-8, or cp1252; quarantine corrupt/binary text."""
    if not raw.strip():
        raise QuarantineError("empty_file")
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise QuarantineError("undecodable_text") from exc
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16", errors="strict")
        except UnicodeDecodeError as exc:
            raise QuarantineError("undecodable_text") from exc
    if b"\x00" in raw:
        raise QuarantineError("undecodable_text")
    for enc in ("utf-8", "cp1252"):
        try:
            text = raw.decode(enc, errors="strict")
        except UnicodeDecodeError:
            continue
        if any(ord(ch) < 32 and ch not in ("\t", "\n", "\r") for ch in text):
            raise QuarantineError("undecodable_text")
        return text
    raise QuarantineError("undecodable_text")


def escape_json_pointer(token: str) -> str:
    """Escape a single RFC 6901 JSON Pointer reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def _check_json_depth(obj: Any, max_depth: int) -> None:
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise QuarantineError("excessive_nesting")
        if isinstance(node, dict):
            for v in node.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(node, list):
            for v in node:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))


def _disambiguate_key(candidate: str, used: set[str]) -> str:
    if candidate not in used:
        return candidate
    idx = 2
    while f"{candidate}__{idx}" in used:
        idx += 1
    return f"{candidate}__{idx}"


def _is_patient_record_array(key: str, value: Any, parent: dict[str, Any]) -> bool:
    """Distinguish patient-record arrays from aggregate/sub-panel arrays."""
    if not (isinstance(value, list) and value and all(isinstance(x, dict) for x in value)):
        return False
    low_k = key.strip().casefold()
    if low_k in _AGGREGATE_ARRAY_KEYS:
        return False
    if low_k in _PATIENT_ARRAY_KEYS:
        return True
    # Check if parent is already a single-patient document
    parent_keys = {str(k).strip().casefold() for k in parent.keys()}
    if parent_keys & {"patient_name", "uhid", "mrn", "dob"}:
        return False
    # Otherwise, check if array items carry patient-identifying fields
    sample_keys = {str(k).strip().casefold() for x in value[:3] for k in x.keys()}
    return bool(sample_keys & _PATIENT_ITEM_HINTS)


def _sanitize_json_node(
    node: Any,
    sanitizer: Sanitizer,
    field_name: str = "",
    in_metadata: bool = False,
    in_fhir_text: bool = False,
    in_fhir_ref: bool = False,
    in_fhir_name: bool = False,
    in_fhir_addr: bool = False,
    in_fhir_subject: bool = False,
) -> tuple[Any, dict[str, str]]:
    """Recursively sanitize JSON values and keys; preserve FHIR references and structured data."""
    if isinstance(node, str):
        if in_fhir_ref:
            return node, {}
        if in_fhir_name or (in_fhir_subject and field_name.strip().casefold() == "display"):
            return sanitizer.sanitize_structured("patient_name", node), {}
        if in_fhir_addr:
            low_f = field_name.strip().casefold()
            if low_f == "city":
                return sanitizer.sanitize_structured("village", node), {}
            if low_f in {"line", "text"}:
                return sanitizer.sanitize_structured("locality", node), {}
        if in_fhir_text:
            return sanitizer.sanitize_fhir_narrative(node), {}
        if field_name and classify_field_name(field_name) is not None:
            return sanitizer.sanitize_structured(field_name, node), {}
        if in_metadata:
            return sanitizer.sanitize_metadata(node), {}
        if field_name:
            return sanitizer.sanitize_structured(field_name, node), {}
        return sanitizer.sanitize_text(node, channel="content"), {}
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        # Catch numeric Aadhaar/Phone stored as JSON numbers under PII keys
        tag = classify_field_name(field_name) if field_name else None
        if tag in {"AADHAAR", "ABHA_NUMBER", "PHONE", "PIN", "MRN"}:
            sanitizer.stats.identifiers_detected += 1
            return f"[{tag}]", {}
        return node, {}
    if isinstance(node, list):
        return [
            _sanitize_json_node(
                x,
                sanitizer,
                field_name=field_name,
                in_metadata=in_metadata,
                in_fhir_text=in_fhir_text,
                in_fhir_ref=in_fhir_ref,
                in_fhir_name=in_fhir_name,
                in_fhir_addr=in_fhir_addr,
                in_fhir_subject=in_fhir_subject,
            )[0]
            for x in node
        ], {}
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        used: set[str] = set()
        key_map: dict[str, str] = {}
        res_type = str(node.get("resourceType", "")).casefold()
        for k, v in node.items():
            clean_k = _disambiguate_key(sanitizer.sanitize_key(k), used)
            used.add(clean_k)
            key_map[k] = clean_k
            low = k.strip().casefold()
            if is_attachment_key(k) and looks_like_encoded_attachment(v):
                is_json, parsed = decode_b64_json(v)
                if is_json:
                    import base64
                    san_sub, _ = _sanitize_json_node(parsed, sanitizer)
                    re_enc = base64.b64encode(json.dumps(san_sub, ensure_ascii=False).encode("utf-8")).decode("ascii")
                    out[clean_k] = re_enc
                else:
                    sanitizer.stats.attachments_removed += 1
                    sanitizer.stats.identifiers_detected += 1
                    out[clean_k] = "[ATTACHMENT_REMOVED]"
            else:
                child_meta = in_metadata or low in {
                    "meta", "metadata", "source", "source_path", "filename", "title", "url", "description"
                }
                child_text = in_fhir_text or low == "div"
                child_ref = in_fhir_ref or low in {"resourcetype", "fullurl", "reference", "system"}
                child_name = in_fhir_name or (low == "name" and res_type in {"patient", "relatedperson", "person"})
                child_addr = in_fhir_addr or (low == "address" and res_type in {"patient", "relatedperson", "person"})
                child_subj = in_fhir_subject or low in {"subject", "patient"}
                # In FHIR, preserve resource.id so Bundle internal references continue to resolve
                if low == "id" and "resourceType" in node:
                    child_ref = True
                out[clean_k] = _sanitize_json_node(
                    v,
                    sanitizer,
                    field_name=k,
                    in_metadata=child_meta,
                    in_fhir_text=child_text,
                    in_fhir_ref=child_ref,
                    in_fhir_name=child_name,
                    in_fhir_addr=child_addr,
                    in_fhir_subject=child_subj,
                )[0]
        return out, key_map
    return node, {}


def process_csv_tsv(
    text: str, delimiter: str, sanitizer: Sanitizer, out_rel: str
) -> tuple[str, list[dict[str, Any]]]:
    """Parse and sanitize CSV/TSV preserving delimiters, headers, and multiline fields."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(text)
            raise QuarantineError("format_mismatch")
        except json.JSONDecodeError:
            pass
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    except csv.Error as exc:
        raise QuarantineError("csv_parse_error") from exc
    if not rows:
        raise QuarantineError("empty_file")

    header, body = rows[0], rows[1:]
    clean_header = [sanitizer.sanitize_header(h) for h in header]
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
    writer.writerow(clean_header)

    records: list[dict[str, Any]] = []
    for idx, row in enumerate(body):
        san_row = [
            sanitizer.sanitize_structured(header[c_idx] if c_idx < len(header) else "", cell)
            for c_idx, cell in enumerate(row)
        ]
        writer.writerow(san_row)
        records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{idx}", "patient": None})
    return buf.getvalue(), records


def process_json_or_fhir(
    text: str, sanitizer: Sanitizer, out_rel: str, max_depth: int = 64
) -> tuple[str, list[dict[str, Any]]]:
    """Parse, depth-check, and sanitize JSON or FHIR R4 Bundle."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise QuarantineError("malformed_json") from exc
    _check_json_depth(data, max_depth=max_depth)

    sanitized, top_key_map = _sanitize_json_node(data, sanitizer)
    records: list[dict[str, Any]] = []
    is_fhir = isinstance(data, dict) and data.get("resourceType") == "Bundle"

    array_keys: list[str] = []
    if isinstance(data, dict) and not is_fhir:
        array_keys = [k for k, v in data.items() if _is_patient_record_array(k, v, data)]

    if not array_keys:
        records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
    else:
        for orig_k in array_keys:
            final_k = top_key_map.get(orig_k, orig_k)
            ptr_k = escape_json_pointer(final_k)
            for i in range(len(data[orig_k])):
                records.append({"file": f"sanitized/{out_rel}", "loc": f"/{ptr_k}/{i}", "patient": None})

    return json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n", records


def process_txt(text: str, sanitizer: Sanitizer, out_rel: str) -> tuple[str, list[dict[str, Any]]]:
    """Sanitize plain text clinical documents."""
    cleaned = sanitizer.sanitize_text(text, channel="content")
    records = [{"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None}]
    return cleaned, records
