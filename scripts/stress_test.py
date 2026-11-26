#!/usr/bin/env python3
"""Standard-scale synthetic stress test (820 files, 5,800+ records) via raksha.toml entrypoint."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLKIT = REPO.parent / "Secret-Wards-ToolKit"


def tree_hash(root: Path, names: tuple[str, ...]) -> str:
    h = hashlib.sha256()
    for name in names:
        p = root / name
        items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.exists() else [])
        for f in items:
            if f.is_file():
                h.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def generate_dataset(inp: Path) -> None:
    (inp / "reg").mkdir(parents=True, exist_ok=True)
    (inp / "opd").mkdir(parents=True, exist_ok=True)
    (inp / "fhir").mkdir(parents=True, exist_ok=True)
    (inp / "notes").mkdir(parents=True, exist_ok=True)
    (inp / "misc").mkdir(parents=True, exist_ok=True)

    # 100 CSV/TSV files x 40 rows = 4,000 records (mixed encodings & renamed headers)
    for i in range(100):
        rows = ["pt_full_nm,contact_num,age,gender,visit_dt,diagnosis"]
        for r in range(40):
            pid = (i * 40 + r) % 400
            rows.append(f"Patient {pid},98765{pid:05d},{25 + (pid % 55)},{'M' if pid % 2 == 0 else 'F'},2025-0{(pid%9)+1}-1{(pid%9)},Dengue")
        content = "\n".join(rows) + "\n"
        if i % 4 == 0:
            (inp / f"reg/h_{i:03d}.tsv").write_bytes(content.replace(",", "\t").encode("utf-16"))
        elif i % 4 == 1:
            (inp / f"reg/h_{i:03d}.csv").write_bytes(content.encode("cp1252"))
        elif i % 4 == 2:
            (inp / f"reg/h_{i:03d}.csv").write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
        else:
            (inp / f"reg/h_{i:03d}.csv").write_text(content, encoding="utf-8")

    # 200 multi-record JSON files x 8 visits = 1,600 records
    for i in range(200):
        visits = [
            {"patient_name": f"Asha {i}_{j}", "phone": f"91234{(i*8+j):05d}", "age": 30 + (j % 40), "visit_date": "2026-03-10"}
            for j in range(8)
        ]
        (inp / f"opd/opd_{i:03d}.json").write_text(json.dumps({"visits": visits}), encoding="utf-8")

    # 100 FHIR Bundles = 100 records
    for i in range(100):
        bundle = {
            "resourceType": "Bundle",
            "type": "document",
            "entry": [{"fullUrl": f"Patient/p{i}", "resource": {"resourceType": "Patient", "id": f"p{i}", "name": [{"text": f"Ravi {i}"}]}}],
        }
        (inp / f"fhir/b_{i:03d}.json").write_text(json.dumps(bundle), encoding="utf-8")

    # 400 multilingual TXT notes = 400 records
    for i in range(400):
        txt = f"नाम: मोहन कुमार {i}\nमोबाइल: 98111{i:05d}\nDr. Sharma reviewed; Dolo 650 1-0-1\nAdmit: 2026-01-10\nDischarge: 2026-01-15\n"
        (inp / f"notes/n_{i:03d}.txt").write_text(txt, encoding="utf-8")

    # 20 malformed / unsupported files
    for i in range(5):
        (inp / f"misc/bad_{i}.pdf").write_bytes(b"%PDF-1.4")
        (inp / f"misc/empty_{i}.txt").write_bytes(b"")
        (inp / f"misc/trunc_{i}.json").write_text('{"a": [1', encoding="utf-8")
        (inp / f"misc/jcsv_{i}.csv").write_text('{"x": 1}', encoding="utf-8")


def main() -> int:
    toml_cfg = tomllib.loads((REPO / "raksha.toml").read_text(encoding="utf-8"))
    run_tpl = toml_cfg["submission"]["run"]

    with tempfile.TemporaryDirectory(prefix="rakshak-stress-") as tmp:
        root = Path(tmp)
        inp = root / "input"
        out_a, out_b, out_c = root / "out_a", root / "out_b", root / "out_c"
        generate_dataset(inp)
        in_before = tree_hash(root, ("input",))

        def run_one(out_dir: Path, secret: str) -> float:
            cmd = run_tpl.replace("{input}", str(inp)).replace("{output}", str(out_dir))
            env = dict(os.environ, RAKSHA_SECRET=secret, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
            t0 = time.monotonic()
            res = subprocess.run(cmd, shell=True, cwd=REPO, env=env, capture_output=True, text=True)
            dt_s = time.monotonic() - t0
            if res.returncode != 0:
                raise RuntimeError(f"Run failed: {res.stderr}")
            return dt_s

        t_a = run_one(out_a, "stress-secret-a")
        run_one(out_b, "stress-secret-a")
        run_one(out_c, "stress-secret-b")
        in_after = tree_hash(root, ("input",))

        rep_a = json.loads((out_a / "report.json").read_text(encoding="utf-8"))
        val = subprocess.run(
            [sys.executable, str(TOOLKIT / "validate_output.py"), "--input", str(inp), "--output", str(out_a)],
            capture_output=True, text=True,
        )
        same_key = tree_hash(out_a, ("sanitized", "records.jsonl")) == tree_hash(out_b, ("sanitized", "records.jsonl"))
        rot_diff = tree_hash(out_a, ("sanitized", "records.jsonl")) != tree_hash(out_c, ("sanitized", "records.jsonl"))

        print("counts:", rep_a["counts"])
        print("wall_s:", round(t_a, 2), "report_timing:", rep_a["timing"], "peak_rss_mb:", rep_a["resources"]["peak_rss_mb"])
        print("input_immutable:", in_before == in_after, "same_key_identical:", same_key, "key_rotation_diff:", rot_diff)
        print("validate_output:", val.stdout.strip())
        assert in_before == in_after
        assert same_key and rot_diff
        assert "CONTRACT OK" in val.stdout
        assert rep_a["counts"]["files_total"] == 820
        assert rep_a["counts"]["files_quarantined"] == 20
        assert rep_a["counts"]["records_processed"] >= 5700
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
