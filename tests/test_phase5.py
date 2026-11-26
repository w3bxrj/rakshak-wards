"""Phase 5 synthetic tests: date shifting, age banding, geo generalization, and channel regressions."""
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
from rakshak.privacy import format_age_band, generalize_ages_in_text, shift_dates_in_text


class Phase5Tests(unittest.TestCase):
    def _run(self, files: dict[str, str], secret: str = "phase5-secret") -> tuple[Path, dict]:
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

    def test_year_boundary_and_leap_day_preserve_intervals(self) -> None:
        # 9-day stay across year boundary
        txt = "Admitted: 2025-12-28T10:15:00+05:30; Discharged: 2026-01-06T09:00:00+05:30; Partial: 2025-12"
        shifted = shift_dates_in_text(txt, 17)
        dates = re.findall(r"\d{4}-\d{2}-\d{2}", shifted)
        self.assertEqual(len(dates), 2)
        d1, d2 = dt.date.fromisoformat(dates[0]), dt.date.fromisoformat(dates[1])
        self.assertEqual((d2 - d1).days, 9)
        self.assertIn("T10:15:00+05:30", shifted)
        self.assertIn("Partial: 2025-12", shifted)

        # Leap day stay (2024-02-28 to 2024-03-01 = 2 days; 2024-02-29 shifted cleanly)
        leap = shift_dates_in_text("Admit: 2024-02-29; Discharge: 2024-03-02", 5)
        ld = [dt.date.fromisoformat(x) for x in re.findall(r"\d{4}-\d{2}-\d{2}", leap)]
        self.assertEqual((ld[1] - ld[0]).days, 2)

    def test_linked_records_across_formats_share_shift_and_unlinked_keeps_los(self) -> None:
        out, _ = self._run({
            "reg/sanjeevani.csv": (
                "mrn,patient_name,dob,age,gender,pin,tehsil,visit_date\n"
                "SNJ-1001,Anita Rao,12/04/1977,48,F,229073,Lalganj,2025-06-30\n"
            ),
            "notes/sanjeevani_note1.txt": "Name: Anita Rao\nUHID: SNJ-1001\nLab Date: 2025-07-05\n",
            "notes/unlinked1.txt": "Admit: 2025-08-01\nDischarge: 2025-08-10\n",
            "notes/unlinked2.txt": "Admit: 2025-08-01\nDischarge: 2025-08-10\n",
        })
        csv_txt = (out / "sanitized/reg/sanjeevani.csv").read_text(encoding="utf-8")
        note_txt = (out / "sanitized/notes/sanjeevani_note1.txt").read_text(encoding="utf-8")
        d_csv = dt.date.fromisoformat(re.search(r"\d{4}-\d{2}-\d{2}", csv_txt).group(0))
        d_note = dt.date.fromisoformat(re.search(r"\d{4}-\d{2}-\d{2}", note_txt).group(0))
        self.assertEqual((d_note - d_csv).days, 5)
        self.assertNotIn("12/04/1977", csv_txt)
        self.assertNotIn("229073", csv_txt)
        self.assertTrue("[PIN]" in csv_txt or "229XXX" in csv_txt)
        self.assertIn("[TEHSIL]", csv_txt)

        # Unlinked records keep patient: null AND exact 9-day LoS with independent offsets
        recs = {r["file"]: r["patient"] for r in (json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines())}
        self.assertIsNone(recs["sanitized/notes/unlinked1.txt"])
        self.assertIsNone(recs["sanitized/notes/unlinked2.txt"])
        u1 = [dt.date.fromisoformat(x) for x in re.findall(r"\d{4}-\d{2}-\d{2}", (out / "sanitized/notes/unlinked1.txt").read_text(encoding="utf-8"))]
        u2 = [dt.date.fromisoformat(x) for x in re.findall(r"\d{4}-\d{2}-\d{2}", (out / "sanitized/notes/unlinked2.txt").read_text(encoding="utf-8"))]
        self.assertEqual((u1[1] - u1[0]).days, 9)
        self.assertEqual((u2[1] - u2[0]).days, 9)
        self.assertNotEqual(u1[0], u2[0])

    def test_age_banding_preserves_durations_and_top_codes_85_plus(self) -> None:
        self.assertEqual(format_age_band(48, 5), "45-49")
        self.assertEqual(format_age_band(91, 5), "85+")
        txt = generalize_ages_in_text("48 Y/F, Dolo 650 x 5 days, HTN x 12 yrs, Hb 70-140", 5)
        self.assertIn("45-49 Y/F", txt)
        self.assertIn("x 5 days", txt)
        self.assertIn("70-140", txt)

    def test_clinician_period_and_channel_regressions(self) -> None:
        self.assertEqual(
            redact_free_text("Reviewed by Dr. Imtiaz Ahmed (MS Surgery).")[0],
            "Reviewed by Dr. Imtiaz Ahmed (MS Surgery).",
        )
        out, _ = self._run({
            "lab/rx_sanjeevani_00065.txt": "Dolo 650\n",
            "opd/test.csv": "Ravi Sharma,SNJ-26-000123,diagnosis\n[PATIENT_NAME],[MRN],Dengue\n",
            "misc/att.json": json.dumps({"scan": "SGVsbG8gd29ybGQgZnJvbSBhdHRhY2htZW50"}),
        })
        self.assertTrue((out / "sanitized/lab/rx_sanjeevani_[MRN].txt").is_file())
        hdr = (out / "sanitized/opd/test.csv").read_text(encoding="utf-8").splitlines()[0]
        self.assertNotIn("Ravi Sharma", hdr)
        self.assertNotIn("SNJ-26-000123", hdr)
        self.assertIn("diagnosis", hdr)
        att = json.loads((out / "sanitized/misc/att.json").read_text(encoding="utf-8"))
        self.assertEqual(att["scan"], "[ATTACHMENT_REMOVED]")


if __name__ == "__main__":
    unittest.main()
