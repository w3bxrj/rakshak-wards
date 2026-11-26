"""Phase 5.1 synthetic tests: clinician preservation, base64 JSON reconstruction, and address patterns."""
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.detect import redact_free_text
from rakshak.pipeline import run_pipeline


class Phase51Tests(unittest.TestCase):
    def _run(self, files: dict[str, str], secret: str = "p51-secret") -> tuple[Path, dict]:
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

    def test_consultant_dr_with_parenthetical_degree_preserved(self) -> None:
        line = "Consultant: Dr. Imtiaz Ahmed (MS Surgery)"
        cleaned, _ = redact_free_text(line)
        self.assertEqual(cleaned, line)

    def test_encoded_json_with_pii_and_harmless_clinical_payload(self) -> None:
        pii_b64 = base64.b64encode(
            json.dumps({"patient_name": "Kiran Rao", "phone": "9876543210"}).encode("utf-8")
        ).decode("ascii")
        clin_b64 = base64.b64encode(
            json.dumps({"test": "HbA1c", "result": "7.2", "unit": "%"}).encode("utf-8")
        ).decode("ascii")
        opaque_b64 = base64.b64encode(b"%PDF-1.4\x00binary\xff\xfe").decode("ascii")

        out, _ = self._run({
            "misc/enc.json": json.dumps({
                "pii_att": {"data": pii_b64},
                "clin_att": {"data": clin_b64},
                "bin_att": {"data": opaque_b64},
            })
        })
        san = json.loads((out / "sanitized/misc/enc.json").read_text(encoding="utf-8"))
        dec_pii = json.loads(base64.b64decode(san["pii_att"]["data"]).decode("utf-8"))
        self.assertEqual(dec_pii["patient_name"], "[PATIENT_NAME]")
        self.assertEqual(dec_pii["phone"], "[PHONE]")

        dec_clin = json.loads(base64.b64decode(san["clin_att"]["data"]).decode("utf-8"))
        self.assertEqual(dec_clin, {"test": "HbA1c", "result": "7.2", "unit": "%"})

        self.assertEqual(san["bin_att"]["data"], "[ATTACHMENT_REMOVED]")

    def test_village_before_tehsil_distt_and_clinical_preservation(self) -> None:
        txt = "142, Ward 20, Mohalla Raja Bazar, Rampur, Tehsil Lalganj, Distt. Rae Bareli; Dolo 650 1-0-1"
        cleaned, _ = redact_free_text(txt)
        self.assertNotIn("Rampur", cleaned)
        self.assertNotIn("142", cleaned)
        self.assertIn("[VILLAGE]", cleaned)
        self.assertIn("Dolo 650 1-0-1", cleaned)


if __name__ == "__main__":
    unittest.main()
