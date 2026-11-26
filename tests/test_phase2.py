"""Phase 2 synthetic unit and contract tests (no dev/truth or attacker data used)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rakshak.ingest import escape_json_pointer
from rakshak.pipeline import run_pipeline
from rakshak.security import derive_date_shift_days, derive_pseudonym

REPO_ROOT = Path(__file__).resolve().parents[1]


def resolve_json_pointer(doc: object, pointer: str) -> object:
    """Resolve an RFC 6901 JSON Pointer against a parsed JSON object."""
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        raise ValueError(f"Invalid pointer: {pointer}")
    cur = doc
    for raw_tok in pointer[1:].split("/"):
        tok = raw_tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(tok)]
        elif isinstance(cur, dict):
            cur = cur[tok]
        else:
            raise KeyError(tok)
    return cur


class Phase2Tests(unittest.TestCase):
    def test_missing_secret_exits_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            inp = tmp_path / "in"
            out = tmp_path / "out_should_not_exist"
            inp.mkdir()
            (inp / "a.txt").write_text("hello", encoding="utf-8")

            env = dict(os.environ)
            env.pop("RAKSHA_SECRET", None)
            res = subprocess.run(
                [sys.executable, str(REPO_ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(out.exists())

            env["RAKSHA_SECRET"] = "   "
            res2 = subprocess.run(
                [sys.executable, str(REPO_ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res2.returncode, 0)
            self.assertFalse(out.exists())

    def test_keyed_derivations_are_domain_separated_and_secret_dependent(self) -> None:
        s1 = b"secret-one"
        s2 = b"secret-two"
        p1 = derive_pseudonym("PT-KEY-1", s1)
        p1_again = derive_pseudonym("PT-KEY-1", s1)
        p2 = derive_pseudonym("PT-KEY-1", s2)
        self.assertEqual(p1, p1_again)
        self.assertNotEqual(p1, p2)
        self.assertTrue(p1.startswith("PSN-"))

        d1 = derive_date_shift_days("PT-KEY-1", s1, max_days=180)
        d1_again = derive_date_shift_days("PT-KEY-1", s1, max_days=180)
        d2 = derive_date_shift_days("PT-KEY-1", s2, max_days=180)
        self.assertEqual(d1, d1_again)
        self.assertNotEqual(d1, 0)
        self.assertNotEqual(d1, d2)

    def test_json_key_collision_and_rfc6901_pointer_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            inp = tmp_path / "in"
            out = tmp_path / "out"
            inp.mkdir()

            payload = {
                "9876543210": [{"rx": "Dolo 650", "dose_mg": 650, "ok": True, "note": None}],
                "9876500000": [{"rx": "Metformin 500", "dose_mg": 500, "ok": False, "note": None}],
                "visits/opd~ward": [{"rx": "ORS", "dose_mg": 200}],
            }
            (inp / "records.json").write_text(json.dumps(payload), encoding="utf-8")

            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret"
            try:
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            san_json = json.loads((out / "sanitized" / "records.json").read_text(encoding="utf-8"))
            self.assertIn("[PHONE]", san_json)
            self.assertIn("[PHONE]__2", san_json)
            self.assertIn("visits/opd~ward", san_json)
            self.assertEqual(san_json["[PHONE]"][0]["dose_mg"], 650)
            self.assertEqual(san_json["[PHONE]__2"][0]["dose_mg"], 500)
            self.assertIs(san_json["[PHONE]"][0]["ok"], True)
            self.assertIsNone(san_json["[PHONE]"][0]["note"])

            recs = [
                json.loads(line)
                for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(recs), 3)
            resolved_rx = [resolve_json_pointer(san_json, r["loc"])["rx"] for r in recs]
            self.assertEqual(sorted(resolved_rx), ["Dolo 650", "Metformin 500", "ORS"])
            self.assertIn(f"/{escape_json_pointer('visits/opd~ward')}/0", [r["loc"] for r in recs])

    def test_quarantine_leaves_no_partial_output_or_dangling_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            inp = tmp_path / "in"
            out = tmp_path / "out"
            inp.mkdir()

            (inp / "bad.pdf").write_bytes(b"%PDF-1.4 binary")
            (inp / "empty.txt").write_bytes(b"")
            (inp / "trunc.json").write_text('{"a": [1, 2', encoding="utf-8")
            (inp / "json_in_csv.csv").write_text('{"a": 1}', encoding="utf-8")
            deep = "[" * 80 + "1" + "]" * 80
            (inp / "deep.json").write_text(deep, encoding="utf-8")
            (inp / "good.csv").write_text('id,note\n1,"line1\nline2"\n', encoding="utf-8")

            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret"
            try:
                report = run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            self.assertEqual(report["counts"]["files_total"], 6)
            self.assertEqual(report["counts"]["files_sanitized"], 1)
            self.assertEqual(report["counts"]["files_quarantined"], 5)
            san_files = list((out / "sanitized").rglob("*"))
            self.assertEqual([p.name for p in san_files if p.is_file()], ["good.csv"])

            recs = [
                json.loads(line)
                for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["file"], "sanitized/good.csv")
            self.assertIn("line1\nline2", (out / "sanitized" / "good.csv").read_text(encoding="utf-8"))

    def test_opaque_base64_attachments_are_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            inp = tmp_path / "in"
            out = tmp_path / "out"
            inp.mkdir()

            payload = {
                "resourceType": "Bundle",
                "type": "document",
                "entry": [
                    {
                        "resource": {
                            "resourceType": "DocumentReference",
                            "content": [{"attachment": {"contentType": "text/plain", "data": "SGVsbG8gd29ybGQgZnJvbSBhdHRhY2htZW50"}}],
                        }
                    }
                ],
            }
            (inp / "bundle.json").write_text(json.dumps(payload), encoding="utf-8")

            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret"
            try:
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            text = (out / "sanitized" / "bundle.json").read_text(encoding="utf-8")
            self.assertNotIn("SGVsbG8gd29ybGQgZnJvbSBhdHRhY2htZW50", text)
            self.assertIn("[ATTACHMENT_REMOVED]", text)


if __name__ == "__main__":
    unittest.main()
