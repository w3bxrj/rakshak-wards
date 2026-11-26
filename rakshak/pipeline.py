"""Core Phase 5 pipeline orchestration: two-pass ingestion, linkage, pseudonymization, and privacy layer."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from rakshak.ingest import (
    SUPPORTED_EXTENSIONS,
    QuarantineError,
    _check_json_depth,
    _is_patient_record_array,
    _sanitize_json_node,
    decode_bytes,
    escape_json_pointer,
)
from rakshak.link import IdentityFeatures, extract_features_from_text, link_and_pseudonymize
from rakshak.privacy import (
    apply_privacy_to_csv_row,
    apply_privacy_to_json,
    apply_privacy_to_text,
    format_age_band,
    infer_month_first,
)
from rakshak.sanitize import Sanitizer
from rakshak.security import (
    derive_date_shift_days,
    derive_record_date_shift_days,
    load_policy,
    peak_rss_mb,
    require_secret,
)


def _disambiguate_rel_path(candidate: str, used: set[str]) -> str:
    if candidate not in used:
        return candidate
    if "." in candidate.rsplit("/", 1)[-1]:
        stem, ext = candidate.rsplit(".", 1)
        idx = 2
        while f"{stem}__{idx}.{ext}" in used:
            idx += 1
        return f"{stem}__{idx}.{ext}"
    idx = 2
    while f"{candidate}__{idx}" in used:
        idx += 1
    return f"{candidate}__{idx}"


def _inject_psn_csv_row(row: list[str], psn: str) -> list[str]:
    out = list(row)
    for idx, cell in enumerate(out):
        if "[MRN]" in cell:
            out[idx] = cell.replace("[MRN]", psn, 1)
            return out
    for idx, cell in enumerate(out):
        if "[PATIENT_NAME]" in cell:
            out[idx] = cell.replace("[PATIENT_NAME]", psn, 1)
            return out
    if out:
        out[0] = f"{psn} {out[0]}".strip()
    return out


def _inject_psn_json(doc: Any, loc: str, psn: str) -> None:
    if isinstance(doc, dict) and doc.get("resourceType") == "Bundle":
        for ent in doc.get("entry") or []:
            res = ent.get("resource") if isinstance(ent, dict) else None
            if isinstance(res, dict) and res.get("resourceType") == "Patient":
                res["identifier"] = [{"system": "urn:rakshak:psn", "value": psn}]
                return
        doc["patient_ref"] = psn
        return
    target = doc
    if loc.startswith("/") and loc != "/":
        for raw_tok in loc[1:].split("/"):
            tok = raw_tok.replace("~1", "/").replace("~0", "~")
            if isinstance(target, list):
                target = target[int(tok)]
            elif isinstance(target, dict):
                target = target[tok]
    if isinstance(target, dict):
        target["patient_ref"] = psn


def _compute_rare_patients(
    all_features: list[IdentityFeatures], psn_map: dict[int, str | None], band_width: int
) -> set[str]:
    """Identify linked patients in small equivalence classes (k < 3) for progressive coarsening."""
    patient_cells: dict[str, tuple[str, str]] = {}
    for idx, feat in enumerate(all_features):
        psn = psn_map.get(idx)
        if not psn:
            continue
        ab = format_age_band(feat.age, band_width) if feat.age is not None else "?"
        g = feat.gender or "?"
        if psn not in patient_cells or (ab != "?" and patient_cells[psn][0] == "?"):
            patient_cells[psn] = (ab, g)
    cell_counts = Counter(patient_cells.values())
    return {psn for psn, cell in patient_cells.items() if cell_counts[cell] < 3}


def run_pipeline(inp: Path, out: Path, policy_path: Path | None = None) -> dict[str, Any]:
    """Run the offline privacy firewall from input dir to output dir."""
    secret = require_secret()
    t0 = time.monotonic()
    policy = load_policy(policy_path) if policy_path else {}
    max_depth = int(policy.get("max_json_depth", 64))
    max_shift = int(policy.get("date_shift_max_days", 180))
    band_width = int(policy.get("age_band_years", 5))

    san_dir = out / "sanitized"
    san_dir.mkdir(parents=True, exist_ok=True)

    sanitizer = Sanitizer()
    files_report: list[dict[str, Any]] = []
    used_out_paths: set[str] = set()

    staged_files: list[dict[str, Any]] = []
    all_features: list[IdentityFeatures] = []
    records: list[dict[str, Any]] = []

    for path in sorted(p for p in inp.rglob("*") if p.is_file()):
        rel = path.relative_to(inp).as_posix()
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        entry: dict[str, Any] = {"input_sha256": sha}
        ext = path.suffix.lower()

        try:
            if ext not in SUPPORTED_EXTENSIONS:
                raise QuarantineError("unsupported_format")
            text = decode_bytes(raw)
            out_rel = _disambiguate_rel_path(sanitizer.sanitize_rel_path(rel), used_out_paths)

            if ext in (".csv", ".tsv"):
                delim = "\t" if ext == ".tsv" else ","
                if text.lstrip().startswith(("{", "[")):
                    try:
                        json.loads(text)
                        raise QuarantineError("format_mismatch")
                    except json.JSONDecodeError:
                        pass
                try:
                    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
                except csv.Error as exc:
                    raise QuarantineError("csv_parse_error") from exc
                if not rows:
                    raise QuarantineError("empty_file")
                header, body = rows[0], rows[1:]
                clean_header = [sanitizer.sanitize_header(h) for h in header]
                san_rows: list[list[str]] = []
                rec_indices: list[int] = []
                for idx, row in enumerate(body):
                    r_idx = len(records)
                    s_fields = {
                        header[c_idx]: cell
                        for c_idx, cell in enumerate(row)
                        if c_idx < len(header)
                    }
                    all_features.append(
                        extract_features_from_text(
                            " ".join(row), r_idx, out_rel, f"row:{idx}", structured_fields=s_fields
                        )
                    )
                    san_rows.append([
                        sanitizer.sanitize_structured(header[c_idx] if c_idx < len(header) else "", cell)
                        for c_idx, cell in enumerate(row)
                    ])
                    records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{idx}", "patient": None})
                    rec_indices.append(r_idx)
                staged_files.append({
                    "kind": "csv", "out_rel": out_rel, "delim": delim,
                    "header": clean_header, "orig_header": header, "rows": san_rows,
                    "rec_indices": rec_indices, "month_first": infer_month_first(text, rel),
                })

            elif ext == ".json":
                try:
                    data = json.loads(text)
                except (json.JSONDecodeError, RecursionError) as exc:
                    raise QuarantineError("malformed_json") from exc
                _check_json_depth(data, max_depth=max_depth)

                is_fhir = isinstance(data, dict) and data.get("resourceType") == "Bundle"
                array_keys: list[str] = []
                if isinstance(data, dict) and not is_fhir:
                    array_keys = [k for k, v in data.items() if _is_patient_record_array(k, v, data)]

                sanitized_doc, top_key_map = _sanitize_json_node(data, sanitizer)
                rec_indices = []
                if not array_keys:
                    r_idx = len(records)
                    s_fields = {k: str(v) for k, v in data.items() if isinstance(v, (str, int))} if isinstance(data, dict) else {}
                    all_features.append(
                        extract_features_from_text(
                            json.dumps(data, ensure_ascii=False), r_idx, out_rel, "doc", structured_fields=s_fields
                        )
                    )
                    records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
                    rec_indices.append(r_idx)
                else:
                    for orig_k in array_keys:
                        final_k = top_key_map.get(orig_k, orig_k)
                        ptr_k = escape_json_pointer(final_k)
                        for i, item in enumerate(data[orig_k]):
                            r_idx = len(records)
                            loc = f"/{ptr_k}/{i}"
                            s_fields = {k: str(v) for k, v in item.items() if isinstance(v, (str, int))} if isinstance(item, dict) else {}
                            all_features.append(
                                extract_features_from_text(
                                    json.dumps(item, ensure_ascii=False), r_idx, out_rel, loc, structured_fields=s_fields
                                )
                            )
                            records.append({"file": f"sanitized/{out_rel}", "loc": loc, "patient": None})
                            rec_indices.append(r_idx)
                staged_files.append({
                    "kind": "json", "out_rel": out_rel, "doc": sanitized_doc, "rec_indices": rec_indices,
                })

            else:
                r_idx = len(records)
                all_features.append(extract_features_from_text(text, r_idx, out_rel, "doc"))
                cleaned = sanitizer.sanitize_text(text, channel="content")
                records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
                staged_files.append({
                    "kind": "txt", "out_rel": out_rel, "text": cleaned,
                    "rec_indices": [r_idx], "month_first": infer_month_first(text, rel),
                })

            used_out_paths.add(out_rel)
            entry.update(output=f"sanitized/{out_rel}", status="sanitized")
        except QuarantineError as exc:
            entry.update(output=None, status="quarantined", reason=exc.reason)
        files_report.append(entry)

    # Pass 2: Conservative cross-script linkage & pseudonym injection
    psn_map = link_and_pseudonymize(all_features, secret)
    for r_idx, psn in psn_map.items():
        records[r_idx]["patient"] = psn

    rare_patients = _compute_rare_patients(all_features, psn_map, band_width)
    records_generalized = 0

    def _offset_for(r_idx: int) -> int:
        psn = psn_map.get(r_idx)
        if psn is not None:
            return derive_date_shift_days(psn, secret, max_days=max_shift)
        rec = records[r_idx]
        return derive_record_date_shift_days(f"{rec['file']}#{rec['loc']}", secret, max_days=max_shift)

    for sf in staged_files:
        dest = san_dir / sf["out_rel"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        if sf["kind"] == "csv":
            buf = io.StringIO()
            w = csv.writer(buf, delimiter=sf["delim"], lineterminator="\n")
            w.writerow(sf["header"])
            for row, r_idx in zip(sf["rows"], sf["rec_indices"]):
                psn = psn_map.get(r_idx)
                row_with_psn = _inject_psn_csv_row(row, psn) if psn else row
                is_rare = psn in rare_patients if psn else False
                bw = band_width * 2 if is_rare else band_width
                priv_row = apply_privacy_to_csv_row(
                    sf["orig_header"],
                    row_with_psn,
                    offset_days=_offset_for(r_idx),
                    band_width=bw,
                    coarsen_geo=is_rare,
                    month_first=sf["month_first"],
                )
                if priv_row != row_with_psn:
                    records_generalized += 1
                w.writerow(priv_row)
            dest.write_text(buf.getvalue(), encoding="utf-8", newline="")
        elif sf["kind"] == "json":
            doc = sf["doc"]
            # Apply privacy per record pointer (or whole doc if doc-level)
            if len(sf["rec_indices"]) == 1 and records[sf["rec_indices"][0]]["loc"] == "doc":
                r_idx = sf["rec_indices"][0]
                psn = psn_map.get(r_idx)
                is_rare = psn in rare_patients if psn else False
                bw = band_width * 2 if is_rare else band_width
                if psn:
                    _inject_psn_json(doc, "doc", psn)
                new_doc = apply_privacy_to_json(doc, offset_days=_offset_for(r_idx), band_width=bw, coarsen_geo=is_rare)
                if new_doc != doc:
                    records_generalized += 1
                doc = new_doc
            else:
                for r_idx in sf["rec_indices"]:
                    psn = psn_map.get(r_idx)
                    loc = records[r_idx]["loc"]
                    is_rare = psn in rare_patients if psn else False
                    bw = band_width * 2 if is_rare else band_width
                    if psn:
                        _inject_psn_json(doc, loc, psn)
                    # Transform the specific record object at loc
                    parts = [raw_tok.replace("~1", "/").replace("~0", "~") for raw_tok in loc[1:].split("/")]
                    parent = doc
                    for tok in parts[:-1]:
                        parent = parent[int(tok)] if isinstance(parent, list) else parent[tok]
                    last_tok = int(parts[-1]) if isinstance(parent, list) else parts[-1]
                    orig_item = parent[last_tok]
                    new_item = apply_privacy_to_json(orig_item, offset_days=_offset_for(r_idx), band_width=bw, coarsen_geo=is_rare)
                    if new_item != orig_item:
                        records_generalized += 1
                    parent[last_tok] = new_item
            dest.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="")
        else:
            r_idx = sf["rec_indices"][0]
            psn = psn_map.get(r_idx)
            is_rare = psn in rare_patients if psn else False
            bw = band_width * 2 if is_rare else band_width
            priv_text = apply_privacy_to_text(
                sf["text"], offset_days=_offset_for(r_idx), band_width=bw, month_first=sf.get("month_first", False)
            )
            if priv_text != sf["text"]:
                records_generalized += 1
            content = f"Patient-Ref: {psn}\n{priv_text}" if psn else priv_text
            dest.write_text(content, encoding="utf-8", newline="")

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    n_san = sum(1 for e in files_report if e["status"] == "sanitized")
    n_quar = len(files_report) - n_san
    n_linked = sum(1 for r in records if r["patient"] is not None)
    rss = peak_rss_mb()

    report: dict[str, Any] = {
        "schema": "raksha-report/1",
        "files": files_report,
        "counts": {
            "files_total": len(files_report),
            "files_sanitized": n_san,
            "files_quarantined": n_quar,
            "records_processed": len(records),
            "identifiers_detected": sanitizer.stats.identifiers_detected,
            "records_linked": n_linked,
            "records_generalized": records_generalized,
            "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.monotonic() - t0, 3)},
        "resources": {"peak_rss_mb": rss},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
