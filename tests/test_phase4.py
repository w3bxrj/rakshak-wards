"""Phase 4 synthetic patient linkage tests (conservative cross-script & anti-over-merging)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.link import IdentityFeatures, link_and_pseudonymize
from rakshak.pipeline import run_pipeline


class Phase4Tests(unittest.TestCase):
    def _run(self, files: dict[str, str], secret: str = "phase4-secret") -> tuple[Path, dict]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        inp, out = root / "in", root / "out"
        for rel, content in files.items():
            p = inp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        old = os.environ.get("RAKSHA_SECRET")
        os.environ["RAKSHA_SECRET"] = secret
        try:
            rep = run_pipeline(inp, out)
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old
        return out, rep

    def test_cross_script_match_with_corroboration(self) -> None:
        out, _ = self._run({
            "opd/sanjeevani_v1.txt": "Name: Mohammad Arif\nDOB: 12/04/1977\nPhone: 9876543210\nBP 120/80\n",
            "rx/sanjeevani_rx.txt": "नाम: मोहम्मद आरिफ\nजन्म तिथि: 12/04/1977\nमोबाइल: 9876543210\nDolo 650\n",
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(recs), 2)
        self.assertIsNotNone(recs[0]["patient"])
        self.assertEqual(recs[0]["patient"], recs[1]["patient"])
        # Verify pseudonym appears inside both sanitized files
        for r in recs:
            txt = (out / r["file"]).read_text(encoding="utf-8")
            self.assertIn(r["patient"], txt)

    def test_two_relatives_sharing_phone_never_merged(self) -> None:
        out, _ = self._run({
            "reg/sanjeevani.csv": (
                "patient_name,age,gender,phone\n"
                "Sunita Devi,28,F,9876543210\n"
                "Ramesh Kumar,55,M,9876543210\n"
            )
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(recs), 2)
        self.assertNotEqual(recs[0]["patient"], recs[1]["patient"])

    def test_identical_mrns_from_different_hospitals_stay_separate(self) -> None:
        out, _ = self._run({
            "reg/sanjeevani.csv": "mrn,patient_name,age\nSNJ-1001,Asha Devi,34\n",
            "reg/arogya.csv": "mrn,patient_name,age\nSNJ-1001,Meena Kumari,61\n",
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(recs), 2)
        self.assertNotEqual(recs[0]["patient"], recs[1]["patient"])

    def test_conflicting_endpoints_in_three_record_chain_prevent_merge(self) -> None:
        # A resembles B (same name+phone, no age/gender on B), B resembles C (same name+phone),
        # but A (age 25, F) conflicts with C (age 62, M) -> must NOT merge all three!
        f_a = IdentityFeatures(0, "a.txt", "doc", phones={"9876543210"}, name_tokens=["kiran", "rao"], gender="F", age=25)
        f_b = IdentityFeatures(1, "b.txt", "doc", phones={"9876543210"}, name_tokens=["kiran", "rao"])
        f_c = IdentityFeatures(2, "c.txt", "doc", phones={"9876543210"}, name_tokens=["kiran", "rao"], gender="M", age=62)
        res = link_and_pseudonymize([f_a, f_b, f_c], b"secret")
        self.assertNotEqual(res[0], res[2])

    def test_unrelated_records_with_identical_placeholders_stay_null(self) -> None:
        out, _ = self._run({
            "notes/n1.txt": "[PATIENT_NAME] [PHONE] [MRN]\n",
            "notes/n2.txt": "[PATIENT_NAME] [PHONE] [MRN]\n",
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(recs), 2)
        self.assertIsNone(recs[0]["patient"])
        self.assertIsNone(recs[1]["patient"])

    def test_traversal_order_invariance_and_secret_rotation(self) -> None:
        files_order_1 = {
            "a_first.txt": "Name: Vivek Joshi\nPhone: 9123456789\n",
            "b_second.txt": "नाम: विवेक जोशी\nमोबाइल: 9123456789\n",
        }
        files_order_2 = {
            "z_first.txt": "Name: Vivek Joshi\nPhone: 9123456789\n",
            "m_second.txt": "नाम: विवेक जोशी\nमोबाइल: 9123456789\n",
        }
        out1, _ = self._run(files_order_1, secret="sec-A")
        out2, _ = self._run(files_order_2, secret="sec-A")
        out3, _ = self._run(files_order_1, secret="sec-B")

        r1 = [json.loads(l) for l in (out1 / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        r2 = [json.loads(l) for l in (out2 / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        r3 = [json.loads(l) for l in (out3 / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

        # Same cluster & same pseudonym regardless of filename order
        self.assertEqual(r1[0]["patient"], r1[1]["patient"])
        self.assertEqual(r2[0]["patient"], r2[1]["patient"])
        self.assertIsNotNone(r1[0]["patient"])
        # Different secret -> different pseudonym, same cluster membership
        self.assertEqual(r3[0]["patient"], r3[1]["patient"])
        self.assertNotEqual(r1[0]["patient"], r3[0]["patient"])


if __name__ == "__main__":
    unittest.main()
