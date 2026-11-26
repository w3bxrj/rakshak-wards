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
| **Practice (`dev/input`, LF, 200 files)** | PII leaked (`check_dev.py`) | `283 / 3230` (`8.8%` overall; `8.3%` Latin, `1.4%` Deva, `29.7%` Hinglish) |
| **Practice (`dev/input`, LF)** | Canaries leaked / Raw copies | `0 / 4` canaries / `0` raw copies (`7` quarantined) |
| **Practice (`dev/input`, LF)** | Medical values kept | `4,854 / 4,855` (`100.0%`) |
| **Practice (`dev/input`, LF)** | Linkage (Precision / Recall / F0.5 / Wrong merges) | `1.00 / 0.54 / 0.85 / 0` |
| **Practice (`dev/input`, LF)** | Age bands | `0 / 527` errors (`24` unresolved; `1` invalid negative source age `-2` excluded) |
| **Practice (`dev/input`, LF)** | Hospital stays (LoS) & cluster date offsets | `337 / 339` checked stays preserved (`2` changed, `1` unresolved); `0 / 90` multi-date output-cluster offset violations |
| **Practice (`dev/input`, LF)** | Person-level privacy proxy (`46 / 48` truth people; `103 / 815` units with complete age+gender+district; `712` skipped) | Size-1 groups: **`46 → 35`**; `< 3` groups: **`46 → 43`** |
| **Standard-Scale Stress Test (820 files, 6,100 recs)** | Elapsed time / Peak RSS (unthrottled Windows host) | `23.65s` wall (`23.43s` reported) / `43.71 MB` |

*(Official automated attacker risk `A1`–`A7` and hidden-dataset scores are unmeasured locally.)*

## Known Limitations

* Unlabeled Hinglish/Latin free-text names and village/PIN fragments without structural anchors still account for the remaining `8.8%` leak tail.
* `2 / 339` checked hospital stays changed length (with `1` additional eligible stay unresolved) on ambiguous mixed-format dates.
* The person-level privacy proxy covers `46` distinct truth people across `103` units with complete `(age, gender, district)` truth annotations (`712` units lack one or more fields); official attacker risk (`A1`–`A7`) remains unmeasured locally.
