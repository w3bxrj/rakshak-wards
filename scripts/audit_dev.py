#!/usr/bin/env python3
"""Evaluation-only truth-based audit script (kept strictly outside production code)."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

_DATE_RX = re.compile(r"\b(\d{4}-\d{2}-\d{2}|\d{2}[/-]\d{2}[/-]\d{4})\b")
_BAND_RX = re.compile(r"\b(\d{1,3})-(\d{1,3})\b|\b(85)\+")


def _parse_dates(text: str, hint: str = "") -> list[dt.date]:
    out: list[dt.date] = []
    fmts = (
        ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y", "%d/%m/%Y", "%d-%m-%Y")
        if hint == "mdy"
        else ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y", "%m-%d-%Y")
    )
    for s in _DATE_RX.findall(text):
        for fmt in fmts:
            try:
                out.append(dt.datetime.strptime(s, fmt).date())
                break
            except ValueError:
                pass
    return out


def _extract_unit_text(out_path: Path, loc: str) -> str:
    if not out_path.is_file():
        return ""
    raw = out_path.read_text(encoding="utf-8", errors="replace")
    if loc.startswith("row:") and out_path.suffix.lower() in {".csv", ".tsv"}:
        import csv, io
        idx = int(loc.split(":", 1)[1])
        delim = "\t" if out_path.suffix.lower() == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(raw, newline=""), delimiter=delim))
        if 1 + idx < len(rows):
            return " ".join(rows[1 + idx])
        return raw
    if loc.startswith("/") and out_path.suffix.lower() == ".json":
        try:
            cur = json.loads(raw)
            for tok in loc[1:].split("/"):
                t = tok.replace("~1", "/").replace("~0", "~")
                cur = cur[int(t)] if isinstance(cur, list) else cur[t]
            return json.dumps(cur, ensure_ascii=False)
        except Exception:
            return raw
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
    out = Path(args.output)
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    renamed = {e.get("input_sha256"): e.get("output") for e in rep.get("files") or []}
    recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    rmap = {(r["file"].replace("sanitized/", "", 1), r["loc"]): r["patient"] for r in recs}

    # 1. Age bands & Date intervals
    age_eligible = age_checked = age_errors = age_unresolved = 0
    los_eligible = los_checked = los_violations = los_unresolved = 0
    patient_offsets: dict[str, list[int]] = {}
    patient_date_checks = patient_offset_violations = 0

    # 2. Person-level privacy proxy (using truth patient ID for same eligible cohort, no shared "?" bucket)
    raw_person_attrs: dict[str, tuple[str, str, str]] = {}
    rel_person_attrs: dict[str, tuple[str, str, str]] = {}
    raw_cluster_attrs: dict[str, tuple[str, str, str]] = {}
    rel_cluster_attrs: dict[str, tuple[str, str, str]] = {}
    missing_fields_count = 0
    eligible_units = 0

    for rel, f in truth["files"].items():
        out_rel = (renamed.get(f["sha256"]) or rel).replace("sanitized/", "", 1)
        p = out / "sanitized" / out_rel
        if not p.is_file():
            continue
        for loc, u in f["units"].items():
            if loc.startswith("@"):
                continue
            eligible_units += 1
            unit_txt = _extract_unit_text(p, loc)
            psn = rmap.get((out_rel, loc)) or rmap.get((out_rel, "doc"))
            true_pid = u.get("patient")
            fields = {fd["kind"]: fd["true"] for fd in (u.get("fields") or []) if isinstance(fd, dict) and "kind" in fd}

            # Age band check (match only 5-yr or 10-yr bands or 85+, never lab ranges like 70-140)
            true_age = fields.get("age")
            if isinstance(true_age, int) and true_age >= 0:
                age_eligible += 1
                bands = [
                    b for b in _BAND_RX.findall(unit_txt)
                    if (b[0] and (int(b[1]) - int(b[0])) in (4, 9) and int(b[1]) <= 120) or b[2]
                ]
                if bands:
                    age_checked += 1
                    ok = any((int(b[0]) <= true_age <= int(b[1])) if b[0] else (true_age >= 85) for b in bands)
                    if not ok:
                        age_errors += 1
                else:
                    age_unresolved += 1

            # Date intervals & per-cluster offset consistency
            dates = u.get("dates") or []
            hint = dates[0].get("hint", "") if dates else ""
            out_dates = _parse_dates(unit_txt, hint=hint)
            if len(dates) >= 2:
                los_eligible += 1
                try:
                    t_dates = sorted(dt.date.fromisoformat(d["true"][:10]) for d in dates)
                    t_gap = (t_dates[-1] - t_dates[0]).days
                    if len(out_dates) >= 2:
                        los_checked += 1
                        if not any(abs((b - a).days) == t_gap for i, a in enumerate(out_dates) for b in out_dates[i + 1 :]):
                            los_violations += 1
                    else:
                        los_unresolved += 1
                except ValueError:
                    los_unresolved += 1

            if psn and len(dates) == 1 and len(out_dates) == 1:
                try:
                    td = dt.date.fromisoformat(dates[0]["true"][:10])
                    off = (out_dates[0] - td).days
                    patient_offsets.setdefault(psn, []).append(off)
                except ValueError:
                    pass

            # Privacy proxy over (age_or_band, gender, district)
            g = fields.get("gender")
            dist = fields.get("district")
            if true_age is None or not isinstance(true_age, int) or true_age < 0 or not g or not dist:
                missing_fields_count += 1
                continue
            m_b = _BAND_RX.search(unit_txt)
            rel_ab = f"{m_b.group(1)}-{m_b.group(2)}" if m_b and m_b.group(1) else ("85+" if m_b else str(true_age))
            rel_dist = "[DISTRICT]" if "[DISTRICT]" in unit_txt else str(dist)
            raw_key = (str(true_age), str(g), str(dist))
            rel_key = (rel_ab, str(g), rel_dist)
            if true_pid:
                raw_person_attrs[true_pid] = raw_key
                rel_person_attrs[true_pid] = rel_key
            if psn:
                raw_cluster_attrs[psn] = raw_key
                rel_cluster_attrs[psn] = rel_key

    for psn, offs in patient_offsets.items():
        if len(offs) >= 2:
            patient_date_checks += 1
            if len(set(offs)) > 1:
                patient_offset_violations += 1

    rper, aper = Counter(raw_person_attrs.values()), Counter(rel_person_attrs.values())
    rclu, aclu = Counter(raw_cluster_attrs.values()), Counter(rel_cluster_attrs.values())

    print(f"AGE_BANDS: eligible={age_eligible}, checked={age_checked}, unresolved={age_unresolved}, errors={age_errors}")
    print(f"LOS_INTERVALS: eligible={los_eligible}, checked={los_checked}, unresolved={los_unresolved}, violations={los_violations}")
    print(f"LINKED_DATE_CONSISTENCY: multi_date_clusters={patient_date_checks}, offset_violations={patient_offset_violations}")
    print(f"PERSON_PROXY_COVERAGE: distinct_truth_people={len(rel_person_attrs)}, total_non_meta_units={eligible_units}, skipped_missing_fields={missing_fields_count}")
    print(f"PERSON_PROXY_BEFORE (size_1={sum(1 for c in rper.values() if c==1)}, lt_3={sum(c for c in rper.values() if c<3)})")
    print(f"PERSON_PROXY_AFTER  (size_1={sum(1 for c in aper.values() if c==1)}, lt_3={sum(c for c in aper.values() if c<3)})")
    print(f"CLUSTER_PROXY (clusters={len(rel_cluster_attrs)}, before_size_1={sum(1 for c in rclu.values() if c==1)}, after_size_1={sum(1 for c in aclu.values() if c==1)}, before_lt3={sum(c for c in rclu.values() if c<3)}, after_lt3={sum(c for c in aclu.values() if c<3)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
