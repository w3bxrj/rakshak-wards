# Team Rakshak — Secret Wards Privacy Firewall

An offline, CPU-only, LLM-free privacy firewall for heterogeneous multilingual Indian hospital records (English, Devanagari Hindi, and Hinglish).

## Setup & Run

```bash
pip install -r requirements.txt
RAKSHA_SECRET=<your-secret> python main.py --input <input-dir> --output <output-dir>
```

* Configured via `raksha.toml` at the repository root (`setup` and `run`).
* Requires a non-empty `RAKSHA_SECRET` environment variable; exits with code `2` before creating any output if missing or empty.
* Runs 100% offline on CPU with zero external API calls or models >50M parameters (pure Python + `PyYAML` + `psutil`).

## Architecture

```text
Input Tree (CSV, TSV, JSON, FHIR R4, TXT, Binary)
  │
  ▼
[1. Resilient Ingestion & Quarantine]  ──(corrupt / unsupported / deep JSON)──▶ Quarantine (report.json)
  │  UTF-8-BOM, UTF-16, UTF-8, cp1252; RFC 6901 pointers; base64 JSON decode
  ▼
[2. Pre-Redaction Feature Extraction]  (in-memory only; never logged or persisted)
  │
  ▼
[3. Multilingual Context-Aware Detection] (EN / Devanagari / Hinglish)
  │  Clinical span protection (Dr., C/O complaint, doses, 1-0-1, eponyms, hospitals)
  │  + structured columns, free-text anchors, headers, keys, metadata, filenames
  ▼
[4. Conservative Cross-Script Linkage]
  │  Phonetic + transliteration + hospital-scoped MRNs + whole-cluster conflict vetoes
  │  + domain-separated HMAC-SHA256 pseudonyms (PSN-XXXXXX)
  ▼
[5. Privacy Transformation Layer]
  │  Per-patient / record-scoped date shifts, 5/10-yr age bands (85+ top-code),
  │  DOB removal, PIN/tehsil/rare-district generalization
  ▼
Output: sanitized/ + report.json + records.jsonl
```

## Core Components & Original Contributions

* **Multilingual Detection (`rakshak/detect.py`, `rakshak/sanitize.py`):** Devanagari digit/script normalization and transliteration paired with clinical span protection (`Dr.`, `C/O <complaint>`, `K/C/O`, `H/O`, doses, `1-0-1`, vitals, eponyms, hospital names) so clinical utility survives intact while English, Hindi, and Hinglish PII is redacted across content, headers, keys, metadata, filenames, and FHIR narratives.
* **Bounded Attachment & JSON Handling (`rakshak/attachments.py`, `rakshak/ingest.py`):** Distinguishes structured `"data"` objects from encoded attachments; decodes base64 JSON within size/depth bounds to sanitize nested PII while preserving harmless clinical payloads, and strips opaque binary payloads (`[ATTACHMENT_REMOVED]`).
* **Conservative Cross-Script Linkage (`rakshak/link.py`):** Combines Indian phonetic skeletons, initial/transliteration matching, hospital-scoped MRNs, and whole-cluster conflict checks (preventing 3-way endpoint-conflict merges and family-phone over-merging). Ambiguous records remain `patient: null`.
* **Privacy Layer (`rakshak/privacy.py`):** Uses separate HMAC-SHA256 domains (`b"psn|"`, `b"shift|"`, `b"recshift|"`) for linked pseudonyms, linked date shifts, and unlinked record-scoped date shifts; infers `MM/DD/YYYY` vs `DD/MM/YYYY` from schema/date evidence; enforces truthful 5-year/10-year age bands and geography generalization.

## Security Design & Data-at-Rest Assumptions

* **Key & Memory Hygiene:** `RAKSHA_SECRET` is read once from `os.environ` into memory and never logged, serialized, or written to disk. Identity features exist solely in RAM during a run.
* **Zero-Leak Logging & Quarantine:** Stdout and `report.json` emit only aggregate counts, input SHA-256 hashes, and fixed enum reason codes (`unsupported_format`, `empty_file`, `undecodable_text`, `malformed_json`, `excessive_nesting`, `format_mismatch`). Unparseable/unsupported files are never copied raw to `sanitized/`.
* **At-Rest Protection:** Input files are read-only and never modified; no plaintext intermediate scratch files are written to disk. Output artifacts (`sanitized/`, `report.json`, `records.jsonl`) are written directly as UTF-8. Reliance on host OS process/RAM isolation and encrypted volume storage is assumed for the execution sandbox.

## Measured Results

| Benchmark | Metric | Measured Value |
| :--- | :--- | :--- |
| **Practice (`dev/input`, 200 files)** | PII leaked (`check_dev.py`) | **`71 / 3,230` (`2.2%` overall; `2.2%` Latin, `0.7%` Deva, `3.6%` Hinglish)** (baseline `b3ac927`: `235 / 3,230`, `7.3%`) |
| **Practice (`dev/input`)** | Canaries leaked / Raw copies | `0 / 4` canaries / `0` raw copies (`7` quarantined) |
| **Practice (`dev/input`)** | Medical values kept | `3,815 / 3,880` (`98.3%`; `61` district coarsenings for `k < 3` privacy) |
| **Practice (`dev/input`)** | Linkage (Precision / Recall / F0.5 / Wrong merges) | `1.00 / 0.50 / 0.83 / 0` |
| **Practice (`dev/input`)** | Age bands & Stay lengths (LoS) | `0 / 464` age-band errors (`5` unresolved); `0 / 325` LoS violations (`1` unresolved); `0 / 70` cluster offset violations |
| **Practice (`dev/input`)** | Person-level privacy proxy (`46` truth people; `103 / 721` units complete) | Size-1 groups: **`46 → 28`**; `< 3` groups: **`46 → 40`** |
| **36-Household Hard (`seed=391870`, 216 visits)** | `base` (shared phone + local MRNs) | **`TP 72 / FP 0 / Mixed HH 0 of 36 / Prec 1.00 / Rec 0.33`** (baseline: `324 FP`, `36/36 mixed`) |
| **36-Household Hard (`seed=391870`)** | `distinct_phones` / `both_removed` / `no_mrns` | `distinct_phones`: `1.00/1.00 (0 mixed)`; `both_removed`: `1.00/1.00 (0 mixed)`; `no_mrns`: **`0 FP, 0/36 mixed`** |
| **Held-Out Cohort (`seed=884422`, 4 files / 5 recs)** | Leaks / Medical kept / Contract | **`0` PII leaks / `10 / 10` medical kept / `CONTRACT OK`** |
| **Standard-Scale Stress Test (820 files, 6,100 recs)** | Elapsed time / Peak RSS (Windows host) | `78.03s` wall (`77.81s` reported) / `50.28 MB` |

*(Official automated attacker risk `A1`–`A7` and hidden-dataset scores are unmeasured locally.)*

## Known Limitations

* Remaining `2.2%` leak tail on `dev/input` is concentrated in filename MRNs (`31 / 850`) and unlabeled village/name fragments without structural anchors.
* `5 / 469` age-band checks and `1 / 326` stay-length checks remain unresolved in `audit_dev.py`; official attacker risk (`A1`–`A7`) remains unmeasured locally.
