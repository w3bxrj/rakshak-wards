"""Phase 6 synthetic regression tests: month-first dates, EN/HI/Hinglish names, and FHIR subject.display."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from rakshak.detect import redact_free_text
from rakshak.pipeline import run_pipeline
from rakshak.privacy import infer_month_first, shift_dates_in_text


class Phase6Tests(unittest.TestCase):
    def _run(self, files: dict[str, str], secret: str = "p6-secret") -> tuple[Path, dict]:
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

    def test_month_first_inference_preserves_5_day_stay(self) -> None:
        txt = "Arogya Seva Sadan\nAdmit: 02/01/2026\nDischarge: 02/06/2026\n"
        self.assertTrue(infer_month_first(txt))
        shifted = shift_dates_in_text(txt, 14, month_first=True)
        dates = [dt.datetime.strptime(s, "%m/%d/%Y").date() for s in re.findall(r"\d{2}/\d{2}/\d{4}", shifted)]
        self.assertEqual((dates[1] - dates[0]).days, 5)

    def test_multilingual_names_paired_with_clinician_and_clinical_values(self) -> None:
        note = (
            "received from Priya Verma's attendant; Dr. Rajesh reviewed; "
            "02-09-2026 रमेश कुमार को 6 दिन बुखार; Priya Verma ki condition stable; Dolo 650 1-0-1"
        )
        cleaned, _ = redact_free_text(note)
        self.assertNotIn("Priya Verma", cleaned)
        self.assertNotIn("रमेश कुमार", cleaned)
        self.assertIn("Dr. Rajesh", cleaned)
        self.assertIn("Dolo 650 1-0-1", cleaned)
        self.assertIn("6 दिन बुखार", cleaned)

    def test_fhir_subject_display_redacted_while_coding_display_preserved(self) -> None:
        bundle = {
            "resourceType": "Bundle",
            "type": "document",
            "entry": [
                {
                    "fullUrl": "Encounter/e1",
                    "resource": {
                        "resourceType": "Encounter",
                        "id": "e1",
                        "subject": {"reference": "Patient/p1", "display": "Anita Sharma"},
                        "reasonCode": [{"coding": [{"code": "A90", "display": "Dengue fever"}]}],
                    },
                }
            ],
        }
        out, _ = self._run({"fhir/b.json": json.dumps(bundle)})
        san = json.loads((out / "sanitized/fhir/b.json").read_text(encoding="utf-8"))
        enc = san["entry"][0]["resource"]
        self.assertEqual(enc["subject"]["reference"], "Patient/p1")
        self.assertEqual(enc["subject"]["display"], "[PATIENT_NAME]")
        self.assertEqual(enc["reasonCode"][0]["coding"][0]["display"], "Dengue fever")


if __name__ == "__main__":
    unittest.main()
