"""Multilingual (English, Devanagari Hindi, Hinglish) context-aware PII detection."""
from __future__ import annotations

import re
from typing import Iterable

_DEVA_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

_DEVA_MAP = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au",
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v",
    "श": "sh", "ष": "sh", "स": "s", "ह": "h", "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ं": "n", "ँ": "n", "्": "", "़": "",
}


def normalize_digits(text: str) -> str:
    return text.translate(_DEVA_DIGITS)


def transliterate_deva(text: str) -> str:
    return "".join(_DEVA_MAP.get(ch, ch) for ch in normalize_digits(text))


# --------------------------------------------------------------------------- clinical protection
_CLINICIAN_RE = re.compile(
    r"(?i)\b(?:Dr|Prof|Doctor|Consultant|Physician)\.?\s*[:=-]?\s*(?:Dr\.?\s*)?[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F.\s]{1,40}?(?:\s*\([^)\n]{1,30}\))?(?=[,\n;]|$|\.(?=\s|$)|\s+(?:reviewed|advised|seen|on|for|at|in|ka|ki|ने|द्वारा)\b)"
    r"|डॉ\.?\s*[\u0900-\u097F]{2,25}(?:\s+[\u0900-\u097F]{2,25})?"
)
_HOSPITAL_RE = re.compile(
    r"(?i)\b[A-Z][A-Za-z&\s]{2,45}?\b(?:Multispecialit?y\s+Hospital|Charitable\s+Hospital|Hospital|Clinic|Medical\s+Cent(?:er|re)|Seva\s+Sadan|Nursing\s+Home|Health\s+Cent(?:er|re)|Dispensary)\b"
)
_COMPLAINT_WORDS = (
    r"fever|cough|cold|pain|chest\s+pain|abdominal\s+pain|headache|vomiting|nausea|diarrh?oea|"
    r"loose\s+motions|breathlessness|dyspnoea|dyspnea|weakness|fatigue|dizziness|vertigo|"
    r"swelling|rash|itching|bleeding|burn|burning|fracture|trauma|injury|syncope|seizure|"
    r"palpitations|edema|oedema|jaundice|anemia|anaemia|diabetes|hypertension|asthma|copd|"
    r"dengue|malaria|typhoid|tb|tuberculosis|uti|uri|lrti|urti|ckd|cad|mi|cva|stroke|"
    r"bukhar|khansi|dard|chakkar|ulti|dast|kamzori|sujan|sans|ghabrahat|तेज\s*बुखार|बुखार|खांसी|दर्द|उल्टी|दस्त|कमजोरी"
)
_CO_COMPLAINT_RE = re.compile(
    rf"(?i)\b(?:C/O|c/o|K/C/O|k/c/o|H/O|h/o|F/H/O|f/h/o)\s+(?:{_COMPLAINT_WORDS})\b[^\n,;.]*"
)
_KCO_HO_RE = re.compile(r"(?i)\b(?:K/C/O|H/O|F/H/O)\s+[^\n,;]+")
_DOSE_VITAL_RE = re.compile(
    r"(?i)\b(?:Tab|Cap|Inj|Syp|Drop|Oint|Susp|Tab\.|Cap\.|Inj\.|Syp\.)\s+[A-Za-z0-9\-\s]{2,30}?\d+(?:\.\d+)?\s*(?:mg|mcg|ml|gm|g|iu|%)\b"
    r"|\b\d+-\d+-\d+\b"
    r"|\b(?:OD|BD|TDS|QID|HS|SOS|STAT)\s*(?:x\s*\d+\s*(?:d|days|wks|weeks))?\b"
    r"|\b(?:BP|PR|HR|RR|SpO2|Temp|Hb|HbA1c|FBS|PPBS|RBS|TLC|PLT|Creatinine|Urea|Bilirubin)\s*[:=]?\s*\d+(?:[./]\d+)?(?:\s*(?:%|mmHg|bpm|mg/dL|g/dL|/uL|F|C))?"
)
_EPONYM_RE = re.compile(
    r"(?i)\b(?:Parkinson'?s|Alzheimer'?s|Addison'?s|Bell'?s|Hodgkin'?s|Graves'?|Cushing'?s|Crohn'?s|Down'?s|Turner'?s|Raynaud'?s|Menier'?s)\b"
)

# --------------------------------------------------------------------------- structured column/key classification
_NON_PATIENT_COL_HINTS = (
    "doctor", "dr_", "clinician", "physician", "consultant", "ward", "hospital",
    "drug", "medicine", "dose", "dosage", "freq", "diagnosis", "dx", "icd",
    "lab", "test", "result", "unit", "range", "vital", "date", "visit_date",
    "admission", "discharge", "age", "gender", "sex", "district", "tehsil", "state",
)

_COL_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("PATIENT_NAME", re.compile(r"(?i)^(?:patient[_\s-]*name|pt[_\s-]*(?:full[_\s-]*)?name|pt_nm|pt_full_nm|full[_\s-]*name|first[_\s-]*name|last[_\s-]*name|fname|lname|given[_\s-]*name|family[_\s-]*name|surname|name|naam|rogi[_\s-]*ka[_\s-]*naam)$")),
    ("RELATIVE_NAME", re.compile(r"(?i)^(?:relative[_\s-]*name|father[_\s-]*name|mother[_\s-]*name|husband[_\s-]*name|spouse[_\s-]*name|guardian[_\s-]*name|care[_\s-]*of|s_o|w_o|d_o|c_o|pita[_\s-]*ka[_\s-]*naam|pati[_\s-]*ka[_\s-]*naam|kin_name|nok_name)$")),
    ("PHONE", re.compile(r"(?i)^(?:phone|phone[_\s-]*no|mobile|mob|mobile[_\s-]*no|contact|contact[_\s-]*no|contact#|tel|telephone|whatsapp|ph_no)$")),
    ("EMAIL", re.compile(r"(?i)^(?:email|e_mail|email[_\s-]*id|mail)$")),
    ("AADHAAR", re.compile(r"(?i)^(?:aadhaar|aadhar|aadhaar[_\s-]*no|aadhar[_\s-]*no|uid|uidai|aadhaar_num)$")),
    ("ABHA_NUMBER", re.compile(r"(?i)^(?:abha|abha[_\s-]*(?:no|number|id|num)|health[_\s-]*id|ndhm[_\s-]*id)$")),
    ("PAN", re.compile(r"(?i)^(?:pan|pan[_\s-]*(?:no|number|card))$")),
    ("INSURANCE_ID", re.compile(r"(?i)^(?:insurance[_\s-]*(?:id|no|number)|policy[_\s-]*(?:no|number)|claim[_\s-]*id|tpa[_\s-]*id|pmjay[_\s-]*id|ayushman[_\s-]*id)$")),
    ("MRN", re.compile(r"(?i)^(?:mrn|uhid|ipd[_\s-]*no|opd[_\s-]*no|reg[_\s-]*no|registration[_\s-]*no|patient[_\s-]*id|pat[_\s-]*id|hospital[_\s-]*id|case[_\s-]*no)$")),
    ("DOB", re.compile(r"(?i)^(?:dob|d\.o\.b|birth[_\s-]*date|date[_\s-]*of[_\s-]*birth|janm[_\s-]*tithi)$")),
    ("HOUSE", re.compile(r"(?i)^(?:house|h[_\s.]*no|house[_\s-]*no|flat[_\s-]*no|plot[_\s-]*no|makan)$")),
    ("LOCALITY", re.compile(r"(?i)^(?:locality|mohalla|colony|sector|nagar|street|gali|address|pata)$")),
    ("LANDMARK", re.compile(r"(?i)^(?:landmark|near)$")),
    ("VILLAGE", re.compile(r"(?i)^(?:village|vill|gram|gaav|gaon|gram[_\s-]*panchayat)$")),
    ("PIN", re.compile(r"(?i)^(?:pin|pincode|pin[_\s-]*code|postal[_\s-]*code|zip)$")),
]


def classify_field_name(field_name: str) -> str | None:
    """Classify a CSV header or JSON key into a PII category if it directly names one."""
    norm = transliterate_deva(field_name).strip()
    norm_compact = re.sub(r"\s+", "_", norm)
    for tag, rx in _COL_RULES:
        if rx.match(norm) or rx.match(norm_compact):
            return tag

    low = norm_compact.casefold()
    if not any(h in low for h in _NON_PATIENT_COL_HINTS):
        if "abha" in low:
            return "ABHA_NUMBER"
        if "aadha" in low or "aadhar" in low:
            return "AADHAAR"
        if any(k in low for k in ("uhid", "mrn", "ipd_no", "opd_no", "reg_no", "pat_id", "patient_id")):
            return "MRN"
        if any(k in low for k in ("insur", "policy_no", "claim_id", "pmjay", "ayushman")):
            return "INSURANCE_ID"
        if any(k in low for k in ("phone", "mobile", "whatsapp", "contact")):
            return "PHONE"
        if any(k in low for k in ("father", "mother", "husband", "spouse", "guardian", "relative")):
            return "RELATIVE_NAME"
        if any(k in low for k in ("patient_name", "pt_name", "full_name", "fname", "lname")):
            return "PATIENT_NAME"
        if any(k in low for k in ("vill", "gram", "gaav", "gaon")):
            return "VILLAGE"
        if any(k in low for k in ("mohalla", "locality", "colony", "pata")):
            return "LOCALITY"
        if "landmark" in low:
            return "LANDMARK"
        if "house" in low or "h_no" in low:
            return "HOUSE"
        if "pincode" in low or "pin_code" in low:
            return "PIN"
        if "dob" in low or "birth_date" in low:
            return "DOB"

    raw = field_name.strip()
    if any(k in raw for k in ("मरीज़ का नाम", "रोगी का नाम", "नाम")):
        return "PATIENT_NAME"
    if any(k in raw for k in ("पिता", "पति", "पुत्र", "पत्नी")):
        return "RELATIVE_NAME"
    if any(k in raw for k in ("मोबाइल", "फ़ोन", "फोन")):
        return "PHONE"
    if "आधार" in raw:
        return "AADHAAR"
    if any(k in raw for k in ("गाँव", "ग्राम")):
        return "VILLAGE"
    if "पता" in raw:
        return "LOCALITY"
    if "पिन" in raw:
        return "PIN"
    if "जन्म" in raw:
        return "DOB"
    return None


# --------------------------------------------------------------------------- free-text patterns
_ID_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("ABHA_NUMBER", re.compile(r"(?<!\d)\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")),
    ("AADHAAR_MASKED", re.compile(r"(?i)(?<![A-Za-z0-9])[X*]{4}[\s-]?[X*]{4}[\s-]?\d{4}(?!\d)")),
    ("AADHAAR", re.compile(r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?91[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}(?!\d)|(?<!\d)0[6-9]\d{9}(?!\d)|(?<!\d)[6-9]\d[X*x]{6}\d{2}(?!\d)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("MRN", re.compile(r"\b[A-Z]{2,5}[/-]\d{2,4}[/-][A-Z0-9-]{3,12}\b")),
    ("MRN", re.compile(r"\b[A-Z]{2,6}-\d{4,10}\b")),
    ("MRN", re.compile(r"(?i)\b(?:UHID|MRN|IPD|OPD|Reg\.?\s*No\.?|Patient\s*ID|Case\s*No\.?|ID|पंजीकरण)\s*[:#/-]\s*([A-Z0-9][A-Z0-9/_-]{3,20})")),
    ("INSURANCE_ID", re.compile(r"(?i)\b(?:Insurance\s*ID|Policy\s*No\.?|Claim\s*ID|TPA\s*ID|PMJAY|Ayushman)\s*[:#/-]\s*([A-Z0-9][A-Z0-9/_-]{3,24})")),
    ("DOB", re.compile(r"(?i)\b(?:DOB|D\.O\.B|Date\s+of\s+Birth|Birth\s+Date|जन्म\s*तिथि)\s*[:=-]\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})")),
    ("HOUSE", re.compile(r"(?i)(?:\bH\.?\s*No\.?|\bHouse\s*No\.?|मकान\s*नं\.?)\s*[:#-]?\s*[A-Za-z0-9/-]{1,12}|\b\d{1,4}(?:/\d{1,3})?(?=\s*,\s*(?:Ward|Mohalla|\[LOCALITY\]|\[HOUSE\]|Near|\[LANDMARK\]))")),
    ("PIN", re.compile(r"(?i)\b(?:PIN|Pin\s*Code|Pincode|पिन)\s*[:=-]\s*([1-9]\d{5})\b|(?:,\s)([1-9]\d{5})\b")),
]

_NAME_LABEL_RE = re.compile(
    r"(?i)(?:Patient\s*Name|Pt\.?\s*Name|Patient|Name|Pt\.|नाम|मरीज़(?:\s*का\s*नाम)?|रोगी(?:\s*का\s*नाम)?)\s*[:=-]\s*([^\n,;|()<>]+?)(?=\s*(?:\d{1,3}\s*/\s*[MF]|S/o|D/o|W/o|C/O|BP\b|PR\b|Age\b|Gender\b|$|[,\n;|()<>]))"
)
_REL_ANCHOR_RE = re.compile(
    r"(?i)\b(?:S/o|D/o|W/o|F/o|M/o|H/o|s/o|d/o|w/o)\s*[:.-]?\s*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F.\s]{1,40}?)(?=\s*(?:[,\n;|()]|\b(?:Age|DOB|H\.No|Ward|Mohalla|Vill|Gram|PIN|BP|की|का|के)\b|$))"
    r"|(?:पुत्र|पुत्री|पत्नी|पिता|पति)\s*[:.-]?\s*([\u0900-\u097FA-Za-z.\s]{2,40}?)(?=[,\n;|()]|$)"
)
_CO_ANCHOR_RE = re.compile(
    r"(?i)\bC/O\s*[:.-]?\s*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F.\s]{1,40}?)(?=\s*(?:[,\n;|()]|\(|$))"
)
_HONORIFIC_NAME_RE = re.compile(
    r"\b([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2})[ \t]+(?:ji|sahab|saheb|bhai|didi|behenji)\b"
    r"|([\u0900-\u097F]{2,20}(?:[ \t]+[\u0900-\u097F]{2,20}){0,2})[ \t]+(?:जी|साहब|दीदी|भाई)\b"
    r"|(?i:\b(?:Mr|Mrs|Ms|Miss|Smt|Shri|Sri|Kumari|Master|Baby)\.?[ \t]+)([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2})\b"
    r"|(?:श्री|श्रीमती|सुश्री|कुमारी)[ \t]+([\u0900-\u097F]{2,20}(?:[ \t]+[\u0900-\u097F]{2,20}){0,2})"
    r"|(?i:\b(?:called[ \t]+by|brought[ \t]+by|accompanied[ \t]+by|received[ \t]+from|attendant|informant|guardian)[ \t]*[:=-]?[ \t]*)([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2})(?='s\b|[ \t]|[,\n]|$)"
    r"|\b\d{1,2}:\d{2}[ \t]*[-–][ \t]*([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2})\b"
    r"|\b([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2})(?='s[ \t]+attendant\b)"
)
_BEFORE_VITALS_OR_AGE_RE = re.compile(
    r"(?:^|(?<=\n)|(?<=;\s)|(?<=\.\s))([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2}|[\u0900-\u097F]{2,20}(?:\s+[\u0900-\u097F]{2,20}){1,2})\s+(?=(?:ka|ki|ke|को|का|की|के)\s+(?:BP|Temp|Pulse|SpO2|sugar|Hb|condition|\d+\s+दिन)\b|\d{1,3}\s*(?:/\s*[MF]|Y\s*/\s*[MF]|Yrs|वर्ष))"
    r"|(?<=note\s)([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2})(?=\s*,\s*(?:S/o|D/o|W/o)\b)"
    r"|(?<=\d{4}\s)([\u0900-\u097F]{2,20}(?:\s+[\u0900-\u097F]{2,20}){1,2})(?=\s+को\s+\d+\s+दिन)"
)
_ADDRESS_TAG_RE: list[tuple[str, re.Pattern[str]]] = [
    ("LOCALITY", re.compile(r"(?i)\b(?:Mohalla|Colony|Nagar|Gali)\s+[A-Za-z\u0900-\u097F0-9.\s]{2,35}?(?=[,\n;|]|$)|मोहल्ला\s+[\u0900-\u097F0-9.\s]{2,35}?(?=[,\n;|]|$)")),
    ("LANDMARK", re.compile(r"(?i)\b(?:Near|Opp\.?|Opposite|Behind)\s+[A-Za-z\u0900-\u097F0-9.\s]{2,35}?(?=[,\n;|]|$)|[\u0900-\u097F0-9.\s]{2,25}\s+के\s+पास(?=[,\n;|]|$)")),
    ("VILLAGE", re.compile(r"(?i)(?:\b(?:Vill\.?|Village|Gram|Gaav)\s*[:.-]?\s*)([A-Za-z\u0900-\u097F.\s]{2,35}?)(?=[,\n;|]|$)|(?:ग्राम|गाँव)\s*[:.-]?\s*([\u0900-\u097F.\s]{2,35}?)(?=[,\n;|]|$)|\b([A-Za-z][A-Za-z\s]{2,28}?)(?=,\s*(?:Tehsil|Taluka|Block|Distt?\.|District)\b)")),
]


def _protected_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for rx in (_CLINICIAN_RE, _HOSPITAL_RE, _CO_COMPLAINT_RE, _KCO_HO_RE, _DOSE_VITAL_RE, _EPONYM_RE):
        for m in rx.finditer(text):
            spans.append((m.start(), m.end()))
    return spans


def _overlaps(start: int, end: int, protected: Iterable[tuple[int, int]]) -> bool:
    return any(start < p_end and end > p_start for p_start, p_end in protected)


def _apply_replacements(text: str, edits: list[tuple[int, int, str]]) -> tuple[str, int]:
    """Apply non-overlapping (start, end, replacement) edits sorted left-to-right."""
    if not edits:
        return text, 0
    edits.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    out: list[str] = []
    cursor = 0
    count = 0
    for s, e, repl in edits:
        if s < cursor or s >= e:
            continue
        out.append(text[cursor:s])
        out.append(repl)
        cursor = e
        count += 1
    out.append(text[cursor:])
    return "".join(out), count


def redact_free_text(text: str) -> tuple[str, int]:
    """Detect and redact multilingual PII in free text while protecting clinical spans."""
    if not text:
        return text, 0

    norm_text = normalize_digits(text)
    protected = _protected_spans(norm_text)
    edits: list[tuple[int, int, str]] = []

    for tag, rx in _ID_PATTERNS:
        for m in rx.finditer(norm_text):
            if m.lastindex:
                grp = next((i for i in range(1, m.lastindex + 1) if m.group(i) is not None), 0)
                s, e = m.start(grp), m.end(grp)
            else:
                s, e = m.start(), m.end()
            if not _overlaps(s, e, protected):
                edits.append((s, e, f"[{tag}]"))

    for tag, rx in _ADDRESS_TAG_RE:
        for m in rx.finditer(norm_text):
            s, e = (m.start(1), m.end(1)) if m.lastindex and m.group(1) else (
                (m.start(2), m.end(2)) if m.lastindex and m.lastindex >= 2 and m.group(2) else (m.start(), m.end())
            )
            if not _overlaps(s, e, protected):
                edits.append((s, e, f"[{tag}]"))

    for m in _REL_ANCHOR_RE.finditer(norm_text):
        grp = 1 if m.group(1) else 2
        s, e = m.start(grp), m.end(grp)
        if not _overlaps(s, e, protected):
            edits.append((s, e, "[RELATIVE_NAME]"))

    for m in _CO_ANCHOR_RE.finditer(norm_text):
        s, e = m.start(1), m.end(1)
        if not _overlaps(s, e, protected):
            edits.append((s, e, "[RELATIVE_NAME]"))

    for m in _NAME_LABEL_RE.finditer(norm_text):
        s, e = m.start(1), m.end(1)
        if not _overlaps(s, e, protected):
            edits.append((s, e, "[PATIENT_NAME]"))

    for rx in (_HONORIFIC_NAME_RE, _BEFORE_VITALS_OR_AGE_RE):
        for m in rx.finditer(norm_text):
            grp = next((i for i in range(1, (m.lastindex or 0) + 1) if m.group(i) is not None), 0)
            s, e = m.start(grp), m.end(grp)
            if not _overlaps(s, e, protected):
                edits.append((s, e, "[PATIENT_NAME]"))

    return _apply_replacements(text, edits)


def redact_structured_value(field_name: str, value: str) -> tuple[str, int]:
    """Redact a structured CSV cell or JSON scalar value using field context + free-text fallback."""
    if not value or not value.strip():
        return value, 0
    if _HOSPITAL_RE.fullmatch(value.strip()) or _CLINICIAN_RE.fullmatch(value.strip()):
        return value, 0
    tag = classify_field_name(field_name)
    if tag is not None:
        if tag == "LOCALITY":
            cleaned, n = redact_free_text(value)
            if n > 0:
                parts = [p.strip() for p in cleaned.split(",")]
                out_parts: list[str] = []
                extra = 0
                for p in parts:
                    if not p or re.fullmatch(r"(?:\[[A-Z_]+\]\s*)+", p):
                        out_parts.append(p)
                    else:
                        out_parts.append("[LOCALITY]")
                        extra += 1
                return ", ".join(out_parts), n + extra
        return f"[{tag}]", 1
    return redact_free_text(value)
