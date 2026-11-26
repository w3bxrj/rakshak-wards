"""Phase 5 privacy transformations: date shifting, age banding, and geography generalization."""
from __future__ import annotations

import datetime as dt
import re
from typing import Any

from rakshak.detect import normalize_digits

# ISO date or datetime (with optional time & timezone)
_ISO_DT_RE = re.compile(
    r"\b(\d{4})-(\d{2})-(\d{2})([T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
# Slash or dash numeric dates: DD/MM/YYYY, DD-MM-YYYY, MM/DD/YYYY
_DMY_RE = re.compile(r"\b(\d{1,2})([/-])(\d{1,2})\2(\d{4})\b")
# Age forms: "48/M", "48 Y / F", "48 Yrs", "48 वर्ष", "Age: 48"
_AGE_SLASH_RE = re.compile(r"(?i)\b(\d{1,3})\s*(?:/\s*([MF])|Y\s*/\s*([MF]))\b")
_AGE_WORD_RE = re.compile(r"(?i)\b(\d{1,3})\s*(Yrs|yrs|years|वर्ष)\b")
_AGE_LABEL_RE = re.compile(r"(?i)\b(Age|उम्र)\s*([:=])\s*(\d{1,3})\b")
# Standalone 6-digit PINs in address/geo context
_PIN_6_RE = re.compile(r"\b([1-9]\d{2})\d{3}\b")

_ELIGIBLE_DATE_KEYS = {
    "date", "visit_date", "admission_date", "admit_date", "discharge_date", "lab_date",
    "sample_date", "report_date", "created_at", "updated_at", "start", "end",
    "effectivedatetime", "authoredon", "issued", "recordeddate", "onsetdatetime",
}
_DOB_KEYS = {"dob", "d.o.b", "birth_date", "date_of_birth", "birthdate", "janm_tithi"}


def infer_month_first(text: str, rel_path: str = "") -> bool:
    """Infer MM/DD/YYYY vs DD/MM/YYYY from explicit format hints, unambiguous dates, or stay-span consistency."""
    low = text[:600].casefold()
    if "mm/dd/yyyy" in low or "mm-dd-yyyy" in low:
        return True
    if "dd/mm/yyyy" in low or "dd-mm-yyyy" in low:
        return False

    has_mdy_only = False
    has_dmy_only = False
    pairs: list[tuple[int, int, int]] = []
    for m in _DMY_RE.finditer(text):
        a, b, y = int(m.group(1)), int(m.group(3)), int(m.group(4))
        pairs.append((a, b, y))
        if b > 12 and a <= 12:
            has_mdy_only = True
        elif a > 12 and b <= 12:
            has_dmy_only = True
    if has_mdy_only and not has_dmy_only:
        return True
    if has_dmy_only and not has_mdy_only:
        return False

    # If all dates are ambiguous (<= 12) and >= 2 dates share the same first number
    # with small variation in the second number (typical short hospital stay in MM/DD),
    # prefer MM/DD over interpreting them as exact-same-day months apart.
    if len(pairs) >= 2:
        firsts = {a for a, _, _ in pairs}
        seconds = [b for _, b, _ in pairs]
        years = {y for _, _, y in pairs}
        if len(firsts) == 1 and len(years) == 1 and len(set(seconds)) > 1 and (max(seconds) - min(seconds)) <= 15:
            return True
    return False


def format_age_band(age: int, width: int = 5) -> str:
    """Return a truthful age band containing `age` (top-coded at 85+)."""
    if age >= 85:
        return "85+"
    if age < 0:
        return "0-4"
    lo = (age // width) * width
    return f"{lo}-{lo + width - 1}"


def _safe_shift_ymd(y: int, m: int, d: int, offset_days: int) -> dt.date | None:
    if not (1900 <= y <= 2100):
        return None
    try:
        return dt.date(y, m, d) + dt.timedelta(days=offset_days)
    except ValueError:
        return None


def shift_dates_in_text(text: str, offset_days: int, month_first: bool = False) -> str:
    """Shift eligible full dates in free text while preserving time, timezone, and partial dates."""
    if not text or offset_days == 0:
        return text

    def _iso_repl(m: re.Match[str]) -> str:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        shifted = _safe_shift_ymd(y, mo, d, offset_days)
        if shifted is None:
            return m.group(0)
        suffix = m.group(4) or ""
        return f"{shifted.strftime('%Y-%m-%d')}{suffix}"

    def _dmy_repl(m: re.Match[str]) -> str:
        a, sep, b, y = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        # Determine day vs month safely
        if a > 12 and 1 <= b <= 12:
            d, mo = a, b
            is_mdy = False
        elif b > 12 and 1 <= a <= 12:
            mo, d = a, b
            is_mdy = True
        elif month_first:
            mo, d = a, b
            is_mdy = True
        else:
            d, mo = a, b
            is_mdy = False
        shifted = _safe_shift_ymd(y, mo, d, offset_days)
        if shifted is None:
            return m.group(0)
        if is_mdy:
            return f"{shifted.month:02d}{sep}{shifted.day:02d}{sep}{shifted.year:04d}"
        return f"{shifted.day:02d}{sep}{shifted.month:02d}{sep}{shifted.year:04d}"

    text = _ISO_DT_RE.sub(_iso_repl, text)
    text = _DMY_RE.sub(_dmy_repl, text)
    return text


def generalize_ages_in_text(text: str, band_width: int = 5) -> str:
    """Replace exact ages in clinical age forms with truthful age bands."""
    if not text:
        return text

    def _slash_repl(m: re.Match[str]) -> str:
        age = int(m.group(1))
        if not (0 <= age <= 120):
            return m.group(0)
        band = format_age_band(age, band_width)
        if m.group(2):
            return f"{band}/{m.group(2).upper()}"
        return f"{band} Y/{m.group(3).upper()}"

    def _word_repl(m: re.Match[str]) -> str:
        prefix = text[max(0, m.start() - 12):m.start()]
        if re.search(r"(?i)(?:\bx|\bfor|\bsince|\bfrom|\bover|\bpast|\blast)\s*$", prefix):
            return m.group(0)
        suffix = text[m.end():m.end() + 10]
        if re.match(r"(?i)\s*(?:back|ago)\b", suffix):
            return m.group(0)
        age = int(m.group(1))
        if not (0 <= age <= 120):
            return m.group(0)
        return f"{format_age_band(age, band_width)} {m.group(2)}"

    def _label_repl(m: re.Match[str]) -> str:
        age = int(m.group(3))
        if not (0 <= age <= 120):
            return m.group(0)
        return f"{m.group(1)}{m.group(2)} {format_age_band(age, band_width)}"

    text = _AGE_SLASH_RE.sub(_slash_repl, text)
    text = _AGE_WORD_RE.sub(_word_repl, text)
    text = _AGE_LABEL_RE.sub(_label_repl, text)
    return text


def generalize_pin(val: str) -> str:
    """Generalize 6-digit PINs to 3-digit prefix (e.g. 229073 -> 229XXX)."""
    return _PIN_6_RE.sub(r"\1XXX", val)


def apply_privacy_to_csv_row(
    header: list[str],
    row: list[str],
    offset_days: int,
    band_width: int = 5,
    coarsen_geo: bool = False,
    month_first: bool = False,
) -> list[str]:
    """Apply date shifting, age banding, and geography generalization to a sanitized CSV row."""
    out: list[str] = []
    for idx, cell in enumerate(row):
        col = header[idx].strip().casefold() if idx < len(header) else ""
        val = cell
        if col in _DOB_KEYS:
            val = "[DOB]"
        elif col in {"age", "umar", "patient_age"}:
            m = re.search(r"\d{1,3}", normalize_digits(val))
            if m and 0 <= int(m.group(0)) <= 120:
                val = format_age_band(int(m.group(0)), band_width)
        elif col in {"pin", "pincode", "pin_code", "postal_code"}:
            val = generalize_pin(val)
        elif col in {"tehsil", "taluka", "block"}:
            val = "[TEHSIL]"
        elif col in {"district", "dist", "distt"} and coarsen_geo:
            val = "[DISTRICT]"
        else:
            val = shift_dates_in_text(val, offset_days, month_first=month_first)
            val = generalize_ages_in_text(val, band_width=band_width)
        out.append(val)
    return out


def apply_privacy_to_json(
    node: Any,
    offset_days: int,
    band_width: int = 5,
    coarsen_geo: bool = False,
    field_name: str = "",
) -> Any:
    """Recursively apply date shifting, age banding, and geography generalization to JSON/FHIR."""
    if isinstance(node, str):
        low = field_name.strip().casefold()
        if low in _DOB_KEYS:
            # Preserve year-only for FHIR birthDate if YYYY-MM-DD, else [DOB]
            m_yr = re.match(r"^(\d{4})-\d{2}-\d{2}$", node.strip())
            return m_yr.group(1) if m_yr else "[DOB]"
        if low in {"age", "umar", "patient_age"}:
            m = re.search(r"\d{1,3}", normalize_digits(node))
            if m and 0 <= int(m.group(0)) <= 120:
                return format_age_band(int(m.group(0)), band_width)
        if low in {"pin", "pincode", "pin_code", "postalcode"}:
            return generalize_pin(node)
        if low in {"tehsil", "taluka", "block"}:
            return "[TEHSIL]"
        if low in {"district", "dist", "distt"} and coarsen_geo:
            return "[DISTRICT]"
        val = shift_dates_in_text(node, offset_days)
        val = generalize_ages_in_text(val, band_width=band_width)
        return val
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        low = field_name.strip().casefold()
        if low in {"age", "umar", "patient_age"} and 0 <= int(node) <= 120:
            return format_age_band(int(node), band_width)
        return node
    if isinstance(node, list):
        return [
            apply_privacy_to_json(x, offset_days, band_width=band_width, coarsen_geo=coarsen_geo, field_name=field_name)
            for x in node
        ]
    if isinstance(node, dict):
        return {
            k: apply_privacy_to_json(v, offset_days, band_width=band_width, coarsen_geo=coarsen_geo, field_name=k)
            for k, v in node.items()
        }
    return node


def apply_privacy_to_text(text: str, offset_days: int, band_width: int = 5, month_first: bool = False) -> str:
    """Apply date shifting and age banding to free-text clinical notes."""
    val = shift_dates_in_text(text, offset_days, month_first=month_first)
    val = generalize_ages_in_text(val, band_width=band_width)
    return val
