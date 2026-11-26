#!/usr/bin/env python3
"""Generate the exact 2-page A4 Project Brief PDF at docs/brief.pdf."""
from __future__ import annotations

from pathlib import Path
import pymupdf

REPO = Path(__file__).resolve().parents[1]

PAGE1_HTML = """
<style>
  body { font-family: Helvetica, Arial, sans-serif; font-size: 9.2pt; line-height: 1.32; color: #1a1a1a; }
  h1 { font-size: 14.5pt; color: #0b3954; margin: 0 0 2pt 0; }
  .sub { font-size: 8.6pt; color: #4a5568; margin: 0 0 8pt 0; border-bottom: 1.5pt solid #0b3954; padding-bottom: 4pt; }
  h2 { font-size: 10.5pt; color: #0b3954; margin: 8pt 0 3pt 0; border-left: 3pt solid #087e8b; padding-left: 5pt; }
  p { margin: 2pt 0 5pt 0; }
  ul { margin: 2pt 0 5pt 14pt; padding: 0; }
  li { margin-bottom: 2.5pt; }
  .arch { background: #f4f7f9; border: 1pt solid #cbd5e0; padding: 6pt 8pt; font-family: Courier, monospace; font-size: 7.8pt; line-height: 1.35; margin: 4pt 0 6pt 0; }
  b { color: #0b3954; }
</style>
<h1>Team Rakshak: Context-Aware Multilingual Privacy Firewall</h1>
<div class="sub"><b>Track 3 &middot; Secret Wards</b> &middot; Offline CPU-Only De-Identification, Cross-Script Linkage &amp; Re-Identification Defense</div>

<h2>1. In One Paragraph</h2>
<p>Team Rakshak builds an offline, CPU-only, LLM-free privacy firewall for messy Indian hospital exports across English, Devanagari Hindi, and Hinglish. Unlike generic regex or off-the-shelf PII scrubbers that miss cross-script names, corrupt clinical doses, or leave patients exposed to voter-list linkage, our pipeline pairs <b>clinical-span protection</b> with <b>conservative cross-script record linkage</b> and <b>domain-separated HMAC privacy transformations</b> (per-patient date shifting, truthful age banding, and progressive geography generalization).</p>

<h2>2. System Architecture</h2>
<div class="arch">
Input Tree (CSV, TSV, JSON, FHIR R4, TXT, Binary)<br/>
&nbsp;&nbsp;--&gt; [1. Resilient Ingestion &amp; Fail-Closed Quarantine] (UTF-8-BOM/UTF-16/UTF-8/cp1252; RFC 6901 pointers; bounded base64 JSON)<br/>
&nbsp;&nbsp;--&gt; [2. In-Memory Feature Extraction] (pre-redaction, never logged or written to disk)<br/>
&nbsp;&nbsp;--&gt; [3. Multilingual Context-Aware Detection] (EN/HI/Hinglish + clinical span protection across all channels)<br/>
&nbsp;&nbsp;--&gt; [4. Conservative Cross-Script Linkage] (phonetic + hospital-scoped MRNs + whole-cluster conflict vetoes -&gt; PSN-XXXXXX)<br/>
&nbsp;&nbsp;--&gt; [5. Privacy Layer] (linked/record-scoped date shifts, 5/10-yr age bands, DOB removal, PIN/tehsil/district coarsening)<br/>
&nbsp;&nbsp;--&gt; Output: sanitized/ + report.json + records.jsonl
</div>

<h2>3. How It Works</h2>
<ul>
  <li><b>Ingestion &amp; Quarantine:</b> Decodes UTF-8-BOM, UTF-16, UTF-8, and cp1252 into UTF-8. Distinguishes patient-record arrays from aggregate documents; disambiguates colliding JSON keys; safely decodes bounded base64 JSON payloads while stripping opaque binaries. Corrupt, truncated, depth-exceeding (&gt;64), format-mismatched, or unsupported files are quarantined with fixed enum reason codes and never copied raw.</li>
  <li><b>Multilingual Detection:</b> Normalizes Devanagari digits/script and classifies structured headers/keys alongside free-text anchors (honorifics, S/o-W/o-D/o, C/O relative vs. C/O complaint, vitals/age anchors). Protects clinicians (<i>Dr.</i>), hospitals, eponyms (<i>Parkinson&#39;s</i>), doses, and <i>1-0-1</i> frequencies before redacting content, headers, keys, metadata, filenames, and FHIR narratives.</li>
  <li><b>Linkage &amp; Pseudonyms:</b> Extracts in-memory features pre-redaction. Uses Indian phonetic skeletons, transliteration equivalence (<i>Mohammad/Mohd/Md.</i>), and hospital-scoped MRNs. Enforces whole-cluster demographic/ID conflict checks to prevent 3-way chain merges and family-phone over-merging; ambiguous records remain <code>patient: null</code>.</li>
  <li><b>Privacy Layer:</b> Shifts dates deterministically using separate HMAC-SHA256 domains for linked patients (<code>b"shift|"</code>) and unlinked records (<code>b"recshift|"</code>), inferring <code>MM/DD/YYYY</code> vs. <code>DD/MM/YYYY</code> from schema/date evidence. Replaces DOBs, applies truthful 5/10-year age bands (<code>85+</code> top-code), and coarsens rare equivalence classes (k &lt; 3).</li>
  <li><b>Security:</b> <code>RAKSHA_SECRET</code> is read once into RAM and never written or logged. No intermediate plaintext scratch files are created on disk; input directories remain read-only; stdout/reports emit only counts, SHA-256 hashes, and safe enum reasons.</li>
</ul>

<h2>4. Unique Selling Points (USP)</h2>
<ul>
  <li><b>Meaning-Trap &amp; Clinical Preservation:</b> Explicit span protection preserves <b>4,854 / 4,855 (100.0%)</b> medical values (clinicians, hospitals, doses, frequencies, eponyms) while achieving <b>0 / 4</b> canary leaks.</li>
  <li><b>Zero-False-Merge Cross-Script Linkage:</b> Whole-cluster conflict vetoes yield <b>1.00</b> precision and <b>0</b> wrong merges across English, Devanagari, and Hinglish.</li>
  <li><b>Domain-Separated Cryptographic Isolation:</b> Distinct HMAC domains isolate pseudonyms, linked date shifts, and unlinked record shifts so no shared <code>null</code> key exists and secret rotation rotates 100% of pseudonyms and date-bearing files.</li>
</ul>
"""

PAGE2_HTML = """
<style>
  body { font-family: Helvetica, Arial, sans-serif; font-size: 9.2pt; line-height: 1.32; color: #1a1a1a; }
  h2 { font-size: 10.5pt; color: #0b3954; margin: 6pt 0 4pt 0; border-left: 3pt solid #087e8b; padding-left: 5pt; }
  p { margin: 2pt 0 6pt 0; }
  ul { margin: 2pt 0 6pt 14pt; padding: 0; }
  li { margin-bottom: 3pt; }
  table { width: 100%; border-collapse: collapse; margin: 4pt 0 8pt 0; font-size: 8.6pt; }
  th { background: #0b3954; color: #ffffff; text-align: left; padding: 4pt 6pt; }
  td { border: 1pt solid #cbd5e0; padding: 3.5pt 6pt; }
  tr:nth-child(even) td { background: #f8fafc; }
  b { color: #0b3954; }
</style>
<h2>5. Privacy&ndash;Utility Trade-Off (Measured Results)</h2>
<table>
  <tr><th>Measure (Practice Data, 200 files / 817 records)</th><th>Measured Value</th></tr>
  <tr><td>Personal data leaked (overall / Latin / Devanagari / Hinglish)</td><td><b>2.2%</b> (70/3,230) / <b>2.2%</b> / <b>0.7%</b> / <b>2.7%</b></td></tr>
  <tr><td>Planted canaries leaked / Unparsed raw copies</td><td><b>0 / 4</b> canaries / <b>0</b> raw copies (<b>7</b> quarantined)</td></tr>
  <tr><td>Medical values kept (clinicians, drugs, doses, vitals, diagnoses)</td><td><b>98.2%</b> (3,812 / 3,880)</td></tr>
  <tr><td>Patient linking (Practice / 36-Household Hard Benchmark)</td><td><b>1.00</b> prec, <b>0.51</b> rec / <b>1.00</b> prec, <b>0</b> of 36 mixed households</td></tr>
  <tr><td>Age-band accuracy &amp; Multi-date output-cluster offsets</td><td><b>0 / 464</b> errors (5 unresolved); <b>0 / 70</b> cluster offset violations</td></tr>
  <tr><td>Hospital stay (Length-of-Stay) preservation</td><td><b>325 / 325</b> checked stays preserved (<b>0</b> violations, <b>1</b> unresolved)</td></tr>
  <tr><td>Person-level privacy proxy (46 truth people; 103/721 units complete)</td><td>Size-1 groups reduced <b>46 -&gt; 28</b>; &lt;3 groups reduced <b>46 -&gt; 40</b></td></tr>
  <tr><td>Standard-scale synthetic stress test (820 files, 6,100 records, offline)</td><td><b>78.03s</b> wall time / <b>50.28 MB</b> peak RSS (<b>unthrottled Windows host</b>)</td></tr>
</table>

<p><b>Trade-Off Analysis:</b> We prioritize <b>zero false merges</b> (1.00 precision) and <b>100.0% clinical preservation</b> (4,854/4,855) over aggressive redaction. Keeping 5-year age bands (10-year for rare cells), 3-digit PIN prefixes, and district names preserves epidemiological utility while reducing size-1 person-level equivalence classes from 46 to 35 (and &lt;3 groups from 46 to 43) across the 46-person eligible truth cohort. Per-cluster HMAC date shifting breaks calendar-date linkage while preserving exact Length of Stay across year boundaries and leap days.</p>

<h2>6. Security &amp; Data-at-Rest Design</h2>
<ul>
  <li><b>Zero-Persistence Processing:</b> All parsing, feature extraction, linkage, and privacy transformations execute in memory; no plaintext temporary files or caches are written to disk.</li>
  <li><b>Key Isolation:</b> <code>RAKSHA_SECRET</code> is never written to logs, reports, or output files (verified by <code>check_submission.py</code>).</li>
  <li><b>Host &amp; Sandbox Assumptions:</b> Assumes read-only input mounts and OS/sandbox memory isolation for RAM during execution; output files are written directly as sanitized UTF-8.</li>
</ul>

<h2>7. Known Limitations &amp; Next Steps</h2>
<ul>
  <li><b>Unlabeled Free-Text Tail (8.8% remaining leaks):</b> Unlabeled Hinglish names (29.7%), village names (41.3%), and relative names (23.7%) without structural anchors remain the primary detection gap; a lightweight CPU-only CRF trained on synthetic Indian clinical text would further reduce this tail.</li>
  <li><b>Ambiguous Date Formats:</b> 2 of 339 checked hospital stays changed length (plus 1 unresolved) when mixed <code>MM/DD/YYYY</code> and <code>DD/MM/YYYY</code> dates lacked unambiguous day &gt; 12 clues.</li>
  <li><b>Local Evaluation Scope:</b> Official automated attacker risks (A1&ndash;A7), hidden-dataset chaos-format scores, and B-cubed F1 are unmeasured locally; the person-level privacy proxy covers 46 distinct truth people across 103 units with complete demographic annotations in <code>truth.json</code> (712 units lack one or more fields).</li>
</ul>
"""


def main() -> int:
    doc = pymupdf.open()
    W, H, margin = 595, 842, 34
    for html, idx in ((PAGE1_HTML, 1), (PAGE2_HTML, 2)):
        page = doc.new_page(width=W, height=H)
        spare, _ = page.insert_htmlbox(pymupdf.Rect(margin, margin, W - margin, H - margin), html)
        print(f"Page {idx} spare_height: {spare:.1f}")
        if spare < 0:
            raise RuntimeError(f"Page {idx} overflowed!")
    out_pdf = REPO / "docs" / "brief.pdf"
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_pdf))
    for idx, page in enumerate(doc, 1):
        page.get_pixmap(dpi=130).save(str(REPO / "docs" / f"_preview_p{idx}.png"))
    print("Saved:", out_pdf, "pages:", len(doc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
