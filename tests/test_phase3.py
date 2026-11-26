"""Phase 3 synthetic regression and paired clinical utility tests."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.detect import redact_free_text
from rakshak.pipeline import run_pipeline


def resolve_json_pointer(doc: object, pointer: str) -> object:
    if pointer == "":
        return doc
    cur = doc
    for raw_tok in pointer[1:].split("/"):
        tok = raw_tok.replace("~1", "/").replace("~0", "~")
        cur = cur[int(tok)] if isinstance(cur, list) else cur[tok]
    return cur


class Phase3Tests(unittest.TestCase):
    def _run(self, files: dict[str, str]) -> tuple[Path, dict]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        inp, out = root / "in", root / "out"
        for rel, content in files.items():
            p = inp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        old = os.environ.get("RAKSHA_SECRET")
        os.environ["RAKSHA_SECRET"] = "phase3-test-secret"
        try:
            rep = run_pipeline(inp, out)
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old
        return out, rep

    def test_record_definition_distinguishes_arrays_aggregates_and_non_patient(self) -> None:
        out, _ = self._run({
            "opd/visits.json": json.dumps({
                "visits": [{"patient_name": "Asha", "age": 30}, {"patient_name": "Ravi", "age": 40}]
            }),
            "clean/census.json": json.dumps({
                "wards": [{"ward": "ICU", "beds": 10}, {"ward": "OPD", "beds": 20}]
            }),
            "clean/formulary.csv": "drug,dose\nDolo,650mg\n",
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        by_file = {}
        for r in recs:
            by_file.setdefault(r["file"], []).append(r["loc"])
        self.assertEqual(by_file["sanitized/opd/visits.json"], ["/visits/0", "/visits/1"])
        self.assertEqual(by_file["sanitized/clean/census.json"], ["doc"])
        self.assertEqual(by_file["sanitized/clean/formulary.csv"], ["row:0"])

    def test_structured_data_field_preserved_and_attachment_metadata_walked(self) -> None:
        out, _ = self._run({
            "lab/report.json": json.dumps({
                "data": {"result": "7.2", "unit": "%"},
                "attachment": {
                    "title": "Patient: Kiran Rao",
                    "data": "SGVsbG8gd29ybGQgZnJvbSBhdHRhY2htZW50",
                },
            })
        })
        san = json.loads((out / "sanitized/lab/report.json").read_text(encoding="utf-8"))
        self.assertEqual(san["data"], {"result": "7.2", "unit": "%"})
        self.assertEqual(san["attachment"]["data"], "[ATTACHMENT_REMOVED]")
        self.assertNotIn("Kiran Rao", san["attachment"]["title"])
        self.assertIn("[PATIENT_NAME]", san["attachment"]["title"])

    def test_clinician_vs_relative_same_name_and_clinical_pairs(self) -> None:
        note = "Dr. Ramesh reviewed patient; C/O Ramesh (brother); H.No. 12"
        cleaned, _ = redact_free_text(note)
        self.assertIn("Dr. Ramesh", cleaned)
        self.assertIn("C/O [RELATIVE_NAME] (brother)", cleaned)
        self.assertIn("[HOUSE]", cleaned)

        self.assertEqual(redact_free_text("C/O fever")[0], "C/O fever")
        self.assertEqual(redact_free_text("C/O Suresh (brother)")[0], "C/O [RELATIVE_NAME] (brother)")
        self.assertEqual(redact_free_text("रमेश कुमार का BP 150/90")[0], "[PATIENT_NAME] का BP 150/90")
        self.assertEqual(redact_free_text("UHID: SNJ/26/064127; Rx: Dolo 650, 1-0-1")[0], "UHID: [MRN]; Rx: Dolo 650, 1-0-1")

    def test_filename_collision_and_fhir_reference_preservation(self) -> None:
        bundle = {
            "resourceType": "Bundle",
            "type": "document",
            "entry": [
                {
                    "fullUrl": "Patient/p1",
                    "resource": {
                        "resourceType": "Patient",
                        "id": "p1",
                        "text": {"status": "generated", "div": "<div>Patient: Meera Devi</div>"},
                        "name": [{"text": "Meera Devi"}],
                        "telecom": [{"system": "phone", "value": "9876543210"}],
                    },
                },
                {
                    "fullUrl": "Encounter/e1",
                    "resource": {
                        "resourceType": "Encounter",
                        "id": "e1",
                        "subject": {"reference": "Patient/p1"},
                    },
                },
            ],
        }
        out, _ = self._run({
            "lab/9876543210_visit.json": json.dumps({"visits": [{"note": "ok"}]}),
            "lab/9876500000_visit.json": json.dumps({"visits": [{"note": "ok2"}]}),
            "fhir/bundle.json": json.dumps(bundle),
        })
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        files = sorted(r["file"] for r in recs)
        self.assertEqual(files, ["sanitized/fhir/bundle.json", "sanitized/lab/[PHONE]_visit.json", "sanitized/lab/[PHONE]_visit__2.json"])
        for r in recs:
            p = out / r["file"]
            self.assertTrue(p.is_file())
            if r["loc"].startswith("/"):
                doc = json.loads(p.read_text(encoding="utf-8"))
                self.assertIn("note", resolve_json_pointer(doc, r["loc"]))

        san_bundle = json.loads((out / "sanitized/fhir/bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(san_bundle["resourceType"], "Bundle")
        self.assertEqual(san_bundle["entry"][0]["fullUrl"], "Patient/p1")
        self.assertEqual(san_bundle["entry"][1]["resource"]["subject"]["reference"], "Patient/p1")
        self.assertNotIn("Meera Devi", json.dumps(san_bundle))
        self.assertNotIn("9876543210", json.dumps(san_bundle))


if __name__ == "__main__":
    unittest.main()
