"""Phase 7 tests: over-merging prevention, transient alias index, locality/village redaction, generic scoping."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.detect import AliasIndex, classify_field_name, redact_free_text, redact_structured_value
from rakshak.link import IdentityFeatures, has_hard_conflict, infer_hospital, link_and_pseudonymize, link_score
from rakshak.pipeline import run_pipeline


class Phase7ImprovementTests(unittest.TestCase):
    def test_village_mohalla_column_classified_despite_age_substring(self) -> None:
        self.assertEqual(classify_field_name("Village/Mohalla"), "VILLAGE")
        self.assertEqual(classify_field_name("Pt_Full_Nm"), "PATIENT_NAME")

    def test_locality_partial_redaction_leaves_no_raw_place(self) -> None:
        cleaned, n = redact_structured_value("address", "H.No. 14, Indiranagar")
        self.assertEqual(cleaned, "[HOUSE], [LOCALITY]")
        self.assertGreaterEqual(n, 2)

    def test_transient_alias_index_protects_clinician_same_name(self) -> None:
        idx = AliasIndex()
        idx.add("Ramesh Kulkarni", is_relative=False)
        idx.compile()
        note = "Dr. Ramesh Kulkarni reviewed; Ramesh ko 3 din se bukhar; Tab. Dolo 650 1-0-1"
        cleaned, _ = redact_free_text(note, alias_index=idx)
        self.assertIn("Dr. Ramesh Kulkarni", cleaned)
        self.assertNotIn("; Ramesh ko", cleaned)
        self.assertIn("[PATIENT_NAME]", cleaned)
        self.assertIn("Dolo 650 1-0-1", cleaned)

    def test_same_issuer_conflicting_mrns_prevent_merge_on_shared_phone(self) -> None:
        a = IdentityFeatures(
            record_idx=0, out_rel="a.csv", loc="row:0", hospital="kgmu",
            scoped_mrns={("kgmu", "KGMU1000")}, phones={"9800112233"},
            name_tokens=["anil", "tiwari"], age=40, gender="M",
        )
        b = IdentityFeatures(
            record_idx=1, out_rel="a.csv", loc="row:1", hospital="kgmu",
            scoped_mrns={("kgmu", "KGMU1001")}, phones={"9800112233"},
            name_tokens=["anil", "tiwari"], age=40, gender="M",
        )
        self.assertTrue(has_hard_conflict(a, b))
        self.assertEqual(link_score(a, b), 0.0)

    def test_near_name_with_disjoint_phones_does_not_merge_on_age_alone(self) -> None:
        a = IdentityFeatures(
            record_idx=0, out_rel="a.csv", loc="row:0", hospital="hospa",
            phones={"9700000001"}, name_tokens=["ramesh", "awasthi"], age=45, gender="M",
        )
        b = IdentityFeatures(
            record_idx=1, out_rel="b.csv", loc="row:0", hospital="hospb",
            phones={"9700000002"}, name_tokens=["ramesha", "awasthi"], age=45, gender="M",
        )
        self.assertEqual(link_score(a, b), 0.0)

    def test_ambiguous_cross_hospital_preserves_within_hospital_links(self) -> None:
        # Two distinct people at Hosp A (ALPH1, ALPH2) sharing phone+name+age, plus one visit at Hosp B (BETA1)
        f0 = IdentityFeatures(
            record_idx=0, out_rel="a.csv", loc="row:0", hospital="alph",
            scoped_mrns={("alph", "ALPH1")}, phones={"9800112233"},
            name_tokens=["rohan", "menon"], age=35, gender="M",
        )
        f1 = IdentityFeatures(
            record_idx=1, out_rel="a.csv", loc="row:1", hospital="alph",
            scoped_mrns={("alph", "ALPH1")}, phones={"9800112233"},
            name_tokens=["rohan", "menon"], age=35, gender="M",
        )
        f2 = IdentityFeatures(
            record_idx=2, out_rel="a.csv", loc="row:2", hospital="alph",
            scoped_mrns={("alph", "ALPH2")}, phones={"9800112233"},
            name_tokens=["rohan", "menon"], age=35, gender="M",
        )
        f3 = IdentityFeatures(
            record_idx=3, out_rel="b.csv", loc="row:0", hospital="beta",
            scoped_mrns={("beta", "BETA1")}, phones={"9800112233"},
            name_tokens=["rohan", "menon"], age=35, gender="M",
        )
        res = link_and_pseudonymize([f0, f1, f2, f3], b"test-secret")
        self.assertEqual(res[0], res[1])
        self.assertNotEqual(res[0], res[2])
        self.assertNotEqual(res[3], res[0])
        self.assertNotEqual(res[3], res[2])

    def test_generic_hospital_inference_works_for_unseen_facilities(self) -> None:
        self.assertEqual(infer_hospital("opd/visits.csv", "Apex Heart Clinic\nPatient: X"), "apexheart")
        self.assertEqual(infer_hospital("kgmu/reg.csv", ""), "kgmu")

    def test_unlabeled_narrative_redacted_via_structured_alias_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "in"
            out = Path(td) / "out"
            inp.mkdir()
            (inp / "reg.csv").write_text("mrn,patient_name,phone\nKGMU-1001,Siddharth Malhotra,9811223344\n", encoding="utf-8")
            (inp / "note.txt").write_text("Siddharth ki tabiyat theek hai; Dr. Kulkarni ne Dolo 650 diya.\n", encoding="utf-8")
            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "unit-secret"
            try:
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old
            san_note = (out / "sanitized" / "note.txt").read_text(encoding="utf-8")
            self.assertNotIn("Siddharth", san_note)
            self.assertIn("Dr. Kulkarni", san_note)
            self.assertIn("Dolo 650", san_note)


if __name__ == "__main__":
    unittest.main()
