"""Conservative, deterministic, cross-script patient record linkage (Phase 4)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from rakshak.detect import (
    _BEFORE_VITALS_OR_AGE_RE,
    _HONORIFIC_NAME_RE,
    _NAME_LABEL_RE,
    classify_field_name,
    normalize_digits,
    transliterate_deva,
)
from rakshak.security import derive_pseudonym

_PLACEHOLDERS = {
    "[patient_name]", "[relative_name]", "[phone]", "[mrn]", "[aadhaar]",
    "[aadhaar_masked]", "[abha_number]", "[pan]", "[email]", "[insurance_id]",
    "[dob]", "[house]", "[locality]", "[landmark]", "[village]", "[pin]",
    "[attachment_removed]", "null", "none", "n/a", "na", "-", "--", "",
}

_GENERIC_NAME_TOKENS = {
    "kumar", "kumari", "devi", "lal", "singh", "sharma", "verma", "gupta", "yadav",
    "ji", "sahab", "saheb", "bhai", "didi", "behenji", "shri", "smt", "mr", "mrs", "ms",
}

_NAME_SYNONYMS = {
    "mohd": "muhammad", "md": "muhammad", "mohammad": "muhammad", "muhammed": "muhammad", "mohammed": "muhammad",
    "smt": "shrimati", "kr": "kumar",
}

_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s.-]?)?([6-9]\d{4}[\s.-]?\d{5})(?!\d)|(?<!\d)0([6-9]\d{9})(?!\d)")
_AADHAAR_RE = re.compile(r"(?<!\d)(\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)")
_ABHA_RE = re.compile(r"(?<!\d)(\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)")
_PAN_RE = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
_EMAIL_RE = re.compile(r"([\w.+-]+@[\w-]+\.[\w.]+)")
_MRN_RE = re.compile(r"\b([A-Z]{2,6}[/-]\d{2,4}[/-][A-Z0-9-]{3,12}|[A-Z]{2,6}-\d{4,10})\b")
_AGE_GENDER_RE = re.compile(r"(?i)\b(\d{1,3})\s*(?:/\s*([MF])|Y\s*/\s*([MF])|(?:Yrs|yrs|years|वर्ष)\s*(?:/\s*([MF]))?)\b")
_DOB_RE = re.compile(r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})\b|\b(\d{4})[/-](\d{1,2})[/-](\d{1,2})\b")
_REL_RE = re.compile(r"(?i)\b(?:S/o|D/o|W/o|F/o|M/o|H/o)\s*[:.-]?\s*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F.\s]{1,35}?)(?=[,\n;|()]|$)")


def _normalize_dob(raw: str) -> str:
    s = normalize_digits(raw).strip()
    m = re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$", s)
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$", s)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if b <= 12:
            return f"{y:04d}-{b:02d}-{a:02d}"
        if a <= 12:
            return f"{y:04d}-{a:02d}-{b:02d}"
    return s


def _clean_tokens(raw: str) -> list[str]:
    if not raw or raw.strip().casefold() in _PLACEHOLDERS:
        return []
    lat = transliterate_deva(raw).casefold()
    toks = re.findall(r"[a-z]+", lat)
    out: list[str] = []
    for t in toks:
        t = _NAME_SYNONYMS.get(t, t)
        if t in _GENERIC_NAME_TOKENS and len(toks) > 1:
            continue
        out.append(t)
    return out


def _phonetic_key(token: str) -> str:
    """Compact Indian-friendly phonetic skeleton (collapses aspirated/vowel variants)."""
    if not token:
        return ""
    s = token.casefold()
    for a, b in (("ph", "f"), ("bh", "b"), ("kh", "k"), ("gh", "g"), ("th", "t"), ("dh", "d"), ("chh", "ch"), ("sh", "s"), ("aa", "a"), ("ee", "i"), ("oo", "u"), ("v", "w")):
        s = s.replace(a, b)
    first = s[0]
    rest = re.sub(r"[aeiouyhw]", "", s[1:])
    # Collapse consecutive duplicates
    dedup = [first]
    for ch in rest:
        if ch != dedup[-1]:
            dedup.append(ch)
    return "".join(dedup)


def name_similarity(t1: list[str], t2: list[str]) -> float:
    """Compute cross-script/initial-aware name similarity in [0, 1]."""
    if not t1 or not t2:
        return 0.0
    s1, s2 = " ".join(t1), " ".join(t2)
    if s1 == s2:
        return 1.0
    # Check phonetic token overlap + initial compatibility
    p1 = [_phonetic_key(x) for x in t1]
    p2 = [_phonetic_key(x) for x in t2]
    if p1 == p2:
        return 0.95
    # Initial match: e.g. ["m", "arif"] vs ["muhammad", "arif"]
    if len(t1) == len(t2) and len(t1) >= 2:
        matches = 0
        for a, b in zip(t1, t2):
            if a == b or _phonetic_key(a) == _phonetic_key(b):
                matches += 1
            elif (len(a) == 1 or len(b) == 1) and a[0] == b[0]:
                matches += 0.85
        if matches >= len(t1) - 0.2:
            return 0.88
    # Unordered token overlap (handles surname-first)
    set1, set2 = set(p1), set(p2)
    jacc = len(set1 & set2) / max(len(set1 | set2), 1)
    seq = SequenceMatcher(None, s1, s2).ratio()
    return max(jacc, seq)


_FACILITY_NAME_RE = re.compile(
    r"(?i)\b([A-Z][A-Za-z&.\s]{2,40}?)\s+(?:Multispecialit?y\s+Hospital|Charitable\s+Hospital|Hospital|Clinic|Medical\s+Cent(?:er|re)|Seva\s+Sadan|Nursing\s+Home|Health\s+Cent(?:er|re)|Dispensary)\b"
)
_GENERIC_PATH_TOKENS = {
    "registration", "reg", "opd", "ipd", "discharge", "notes", "note", "rx", "lab", "labs",
    "fhir", "export", "exports", "data", "records", "record", "patients", "patient",
    "visits", "visit", "admissions", "claims", "csv", "tsv", "json", "txt", "input", "sanitized",
}
_GENERIC_MRN_PREFIXES = {"UHID", "MRN", "IPD", "OPD", "REG", "HOSP", "PAT", "CASE", "ID"}


def infer_hospital(rel_path: str, text: str = "") -> str:
    """Infer a normalized facility scope from text headers, file path tokens, or MRN prefixes."""
    if text:
        m = _FACILITY_NAME_RE.search(text[:600])
        if m:
            slug = re.sub(r"[^a-z0-9]+", "", m.group(1).casefold())
            if len(slug) >= 2:
                return slug
    # Check path directory / filename stem tokens (excluding generic channel names)
    for part in rel_path.replace("\\", "/").split("/"):
        stem = part.rsplit(".", 1)[0]
        for tok in re.split(r"[^A-Za-z]+", stem):
            low = tok.casefold()
            if len(low) >= 3 and low not in _GENERIC_PATH_TOKENS:
                return low
    return "generic"


def _mrn_scope(mrn_raw: str, default_hospital: str) -> str:
    """Use explicit non-generic MRN prefix as scope when present, else fall back to facility scope."""
    m = re.match(r"^([A-Za-z]{2,6})[/-]", mrn_raw.strip())
    if m:
        prefix = m.group(1).upper()
        if prefix not in _GENERIC_MRN_PREFIXES:
            return prefix.casefold()
    return default_hospital


@dataclass
class IdentityFeatures:
    """In-memory identity features for a single record (never persisted or logged)."""

    record_idx: int
    out_rel: str
    loc: str
    hospital: str = "generic"
    scoped_mrns: set[tuple[str, str]] = field(default_factory=set)
    strong_ids: set[tuple[str, str]] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    name_tokens: list[str] = field(default_factory=list)
    rel_tokens: list[str] = field(default_factory=list)
    gender: str | None = None
    age: int | None = None
    dob: str | None = None
    pin: str | None = None
    district: str | None = None
    has_deva: bool = False

    def has_identity_anchor(self) -> bool:
        return bool(self.strong_ids or self.scoped_mrns or self.phones or self.name_tokens)

    def canonical_signature(self) -> str:
        """Order-independent signature for deterministic cluster sorting."""
        parts = [
            ",".join(f"{t}:{v}" for t, v in sorted(self.strong_ids)),
            ",".join(f"{h}:{m}" for h, m in sorted(self.scoped_mrns)),
            ",".join(sorted(self.phones)),
            " ".join(self.name_tokens),
            self.dob or "",
            str(self.age or ""),
            self.gender or "",
            f"{self.out_rel}#{self.loc}",
        ]
        return "|".join(parts)


def extract_features_from_text(
    text: str, record_idx: int, out_rel: str, loc: str, structured_fields: dict[str, str] | None = None
) -> IdentityFeatures:
    """Extract minimal in-memory identity features before redaction."""
    feat = IdentityFeatures(
        record_idx=record_idx,
        out_rel=out_rel,
        loc=loc,
        hospital=infer_hospital(out_rel, text),
        has_deva=bool(re.search(r"[\u0900-\u097F]", text)),
    )
    norm = normalize_digits(text)

    for m in _EMAIL_RE.finditer(norm):
        feat.strong_ids.add(("EMAIL", m.group(1).casefold()))
    for m in _PAN_RE.finditer(norm):
        feat.strong_ids.add(("PAN", m.group(1).upper()))
    for m in _ABHA_RE.finditer(norm):
        digits = re.sub(r"\D", "", m.group(1))
        if len(digits) == 14:
            feat.strong_ids.add(("ABHA", digits))
    for m in _AADHAAR_RE.finditer(norm):
        digits = re.sub(r"\D", "", m.group(1))
        if len(digits) == 12:
            feat.strong_ids.add(("AADHAAR", digits))
    for m in _PHONE_RE.finditer(norm):
        digits = re.sub(r"\D", "", m.group(1) or m.group(2))
        if len(digits) == 10:
            feat.phones.add(digits)
    for m in _MRN_RE.finditer(norm):
        raw_mrn = m.group(1)
        feat.scoped_mrns.add((_mrn_scope(raw_mrn, feat.hospital), re.sub(r"[^A-Z0-9]", "", raw_mrn.upper())))

    ag = _AGE_GENDER_RE.search(norm)
    if ag:
        age_val = int(ag.group(1))
        if 0 <= age_val <= 120:
            feat.age = age_val
        g = ag.group(2) or ag.group(3) or ag.group(4)
        if g:
            feat.gender = g.upper()

    rm = _REL_RE.search(norm)
    if rm:
        feat.rel_tokens = _clean_tokens(rm.group(1))

    # Free-text name extraction fallback (labels, honorifics, vitals/age anchors)
    if not feat.name_tokens:
        for rx in (_NAME_LABEL_RE, _HONORIFIC_NAME_RE, _BEFORE_VITALS_OR_AGE_RE):
            m_name = rx.search(norm)
            if m_name:
                grp = next((i for i in range(1, (m_name.lastindex or 0) + 1) if m_name.group(i) is not None), 0)
                toks = _clean_tokens(m_name.group(grp))
                if toks:
                    feat.name_tokens = toks
                    break

    if structured_fields:
        for k, v in structured_fields.items():
            if not v or v.strip().casefold() in _PLACEHOLDERS:
                continue
            kl = k.strip().casefold()
            ftag = classify_field_name(k)
            if (ftag == "PATIENT_NAME" or kl in {"patient_name", "name", "full_name", "first_name", "fname", "pt_name"}) and not feat.name_tokens:
                feat.name_tokens = _clean_tokens(v)
            elif kl in {"last_name", "lname", "surname"}:
                feat.name_tokens.extend(_clean_tokens(v))
            elif kl in {"gender", "sex"} and not feat.gender:
                gv = v.strip().upper()[:1]
                if gv in {"M", "F"}:
                    feat.gender = gv
            elif kl == "age" and feat.age is None:
                m_age = re.search(r"\d{1,3}", normalize_digits(v))
                if m_age and 0 <= int(m_age.group(0)) <= 120:
                    feat.age = int(m_age.group(0))
            elif (ftag == "DOB" or kl in {"dob", "birth_date", "date_of_birth", "birthdate"}) and not feat.dob:
                feat.dob = _normalize_dob(v)
            elif (ftag == "PIN" or kl in {"pin", "pincode", "pin_code"}) and not feat.pin:
                m_pin = re.search(r"[1-9]\d{5}", normalize_digits(v))
                if m_pin:
                    feat.pin = m_pin.group(0)
            elif kl in {"district", "dist", "distt"} and not feat.district:
                feat.district = v.strip().casefold()
            elif ftag == "MRN" or kl in {"mrn", "uhid", "ipd_no", "opd_no", "reg_no", "patient_id"}:
                raw_mrn = normalize_digits(v).strip()
                mrn_clean = re.sub(r"[^A-Z0-9]", "", raw_mrn.upper())
                if len(mrn_clean) >= 4:
                    feat.scoped_mrns.add((_mrn_scope(raw_mrn, feat.hospital), mrn_clean))

    return feat


def has_hard_conflict(a: IdentityFeatures, b: IdentityFeatures) -> bool:
    """Return True if two records have contradictory demographic or identifier evidence."""
    if a.gender and b.gender and a.gender != b.gender:
        return True
    if a.age is not None and b.age is not None and abs(a.age - b.age) > 3:
        return True
    if a.dob and b.dob and a.dob != b.dob:
        return True
    # Conflicting national/unique IDs of the same type
    for id_type in ("AADHAAR", "ABHA", "PAN"):
        a_ids = {v for t, v in a.strong_ids if t == id_type}
        b_ids = {v for t, v in b.strong_ids if t == id_type}
        if a_ids and b_ids and not (a_ids & b_ids):
            return True
    # Conflicting local MRNs from the same non-generic issuer/hospital
    a_issuers = {h for h, _ in a.scoped_mrns if h != "generic"}
    b_issuers = {h for h, _ in b.scoped_mrns if h != "generic"}
    for issuer in a_issuers & b_issuers:
        a_mrns = {m for h, m in a.scoped_mrns if h == issuer}
        b_mrns = {m for h, m in b.scoped_mrns if h == issuer}
        if a_mrns and b_mrns and not (a_mrns & b_mrns):
            return True
    # Conflicting names when both are present
    if a.name_tokens and b.name_tokens and name_similarity(a.name_tokens, b.name_tokens) < 0.45:
        return True
    # Conflicting relatives when both are present
    if a.rel_tokens and b.rel_tokens and name_similarity(a.rel_tokens, b.rel_tokens) < 0.45:
        return True
    return False


def link_score(a: IdentityFeatures, b: IdentityFeatures) -> float:
    """Return positive linkage score if corroborated, else 0.0."""
    if has_hard_conflict(a, b):
        return 0.0

    # Tier 1: Shared strong national ID or non-generic hospital-scoped MRN
    if a.strong_ids & b.strong_ids:
        return 10.0
    shared_mrns = a.scoped_mrns & b.scoped_mrns
    if any(h != "generic" for h, _ in shared_mrns):
        return 9.0
    if shared_mrns and a.name_tokens and b.name_tokens and name_similarity(a.name_tokens, b.name_tokens) >= 0.70:
        return 8.5

    nsim = name_similarity(a.name_tokens, b.name_tokens)
    shared_phone = bool(a.phones & b.phones)

    # Tier 2a: Shared phone + compatible name (or corroborated demographics)
    if shared_phone:
        if a.name_tokens and b.name_tokens and nsim >= 0.60:
            # Same-script Latin near-names (e.g. Ramesh vs Ramesha) sharing a household phone
            # need exact token match, initials, or DOB/relative corroboration.
            is_cross_script = a.has_deva != b.has_deva
            has_initial = any(len(t) == 1 for t in a.name_tokens + b.name_tokens)
            has_distinguishing = (
                (a.dob and b.dob and a.dob == b.dob)
                or (a.rel_tokens and b.rel_tokens and name_similarity(a.rel_tokens, b.rel_tokens) >= 0.70)
            )
            if a.name_tokens == b.name_tokens:
                return 8.0
            if is_cross_script or has_initial or has_distinguishing:
                return 7.0 + nsim * 0.9
            return 0.0
        if (not a.name_tokens or not b.name_tokens) and (
            (a.age is not None and b.age is not None and abs(a.age - b.age) <= 2)
            or (a.dob and b.dob and a.dob == b.dob)
        ):
            return 6.0

    # Tier 2b: No shared strong ID, MRN, or phone.
    # Disjoint phones without a shared ID/MRN must not merge on name+age alone.
    if a.phones and b.phones and not shared_phone:
        return 0.0

    # Strong cross-script / phonetic multi-token name match + distinguishing corroboration (DOB or relative)
    if nsim >= 0.80 and len(a.name_tokens) >= 2 and len(b.name_tokens) >= 2:
        corroborations = 0
        if a.dob and b.dob and a.dob == b.dob:
            corroborations += 2
        if a.rel_tokens and b.rel_tokens and name_similarity(a.rel_tokens, b.rel_tokens) >= 0.75:
            corroborations += 2
        if corroborations >= 2:
            bonus = 0.2 if (a.age is not None and b.age is not None and abs(a.age - b.age) <= 2) else 0.0
            return 5.0 + nsim + bonus

    return 0.0


def _find_ambiguous_phones(features: list[IdentityFeatures]) -> set[str]:
    """Identify phones shared across multiple distinct names or repeated in the same file without IDs."""
    by_phone: dict[str, list[IdentityFeatures]] = {}
    for f in features:
        for ph in f.phones:
            by_phone.setdefault(ph, []).append(f)

    ambiguous: set[str] = set()
    for ph, feats in by_phone.items():
        if len(feats) < 2:
            continue
        # 1. Phone shared across incompatible names
        named = [f for f in feats if f.name_tokens]
        if len(named) >= 2:
            base_tokens = named[0].name_tokens
            if any(name_similarity(base_tokens, other.name_tokens) < 0.90 for other in named[1:]):
                ambiguous.add(ph)
                continue
        # 2. Phone appears >= 2 times in the same file without identical strong ID or MRN
        by_file: dict[str, list[IdentityFeatures]] = {}
        for f in feats:
            by_file.setdefault(f.out_rel, []).append(f)
        for file_feats in by_file.values():
            if len(file_feats) >= 2:
                # Check if they lack a common strong ID or MRN
                has_common_id = all(
                    (file_feats[0].strong_ids & other.strong_ids) or (file_feats[0].scoped_mrns & other.scoped_mrns)
                    for other in file_feats[1:]
                )
                if not has_common_id:
                    ambiguous.add(ph)
                    break
    return ambiguous


def link_and_pseudonymize(
    features: list[IdentityFeatures], secret: bytes
) -> dict[int, str | None]:
    """Cluster records conservatively with whole-cluster conflict checks and assign HMAC pseudonyms."""
    n = len(features)
    ambiguous_phones = _find_ambiguous_phones(features)
    # Build candidate edges
    edges: list[tuple[float, str, str, int, int]] = []
    for i in range(n):
        fi = features[i]
        if not fi.has_identity_anchor():
            continue
        for j in range(i + 1, n):
            fj = features[j]
            if not fj.has_identity_anchor():
                continue
            sc = link_score(fi, fj)
            if 0.0 < sc < 8.5:
                shared_ph = fi.phones & fj.phones
                if shared_ph and shared_ph.issubset(ambiguous_phones):
                    has_distinguishing = (
                        (fi.dob and fj.dob and fi.dob == fj.dob)
                        or (fi.rel_tokens and fj.rel_tokens and name_similarity(fi.rel_tokens, fj.rel_tokens) >= 0.70)
                    )
                    if not has_distinguishing:
                        continue
            if sc > 0.0:
                s_i, s_j = fi.canonical_signature(), fj.canonical_signature()
                lo, hi = (s_i, s_j) if s_i <= s_j else (s_j, s_i)
                edges.append((-sc, lo, hi, i, j))

    # Deterministic order independent of file traversal order
    edges.sort()

    clusters: dict[int, list[int]] = {i: [i] for i in range(n)}
    owner: dict[int, int] = {i: i for i in range(n)}

    # Pass 1: Merge high-confidence issuer/national-ID edges (>= 8.5) first
    for neg_sc, _, _, i, j in edges:
        if -neg_sc < 8.5:
            continue
        ci, cj = owner[i], owner[j]
        if ci == cj:
            continue
        members_i, members_j = clusters[ci], clusters[cj]
        if any(has_hard_conflict(features[u], features[v]) for u in members_i for v in members_j):
            continue
        for v in members_j:
            owner[v] = ci
        members_i.extend(members_j)
        del clusters[cj]

    # Build cluster-level candidate scores for remaining Tier 2 edges (< 8.5)
    # so we can detect competing, mutually-incompatible candidate clusters.
    cluster_best: dict[tuple[int, int], float] = {}
    for neg_sc, _, _, i, j in edges:
        sc = -neg_sc
        if sc >= 8.5:
            continue
        ci, cj = owner[i], owner[j]
        if ci == cj:
            continue
        members_i, members_j = clusters[ci], clusters[cj]
        if any(has_hard_conflict(features[u], features[v]) for u in members_i for v in members_j):
            continue
        pair = (ci, cj) if ci < cj else (cj, ci)
        if sc > cluster_best.get(pair, 0.0):
            cluster_best[pair] = sc

    def _has_competing_candidate(src_c: int, dst_c: int, sc: float) -> bool:
        for (a_c, b_c), alt_sc in cluster_best.items():
            other = b_c if a_c == src_c else (a_c if b_c == src_c else None)
            if other is None or other == dst_c or other not in clusters:
                continue
            if alt_sc >= sc - 0.5:
                if any(has_hard_conflict(features[u], features[v]) for u in clusters[dst_c] for v in clusters[other]):
                    return True
        return False

    # Pass 2: Merge Tier 2 edges only when neither side has a competing incompatible cluster
    for neg_sc, _, _, i, j in edges:
        sc = -neg_sc
        if sc >= 8.5:
            continue
        ci, cj = owner[i], owner[j]
        if ci == cj:
            continue
        members_i, members_j = clusters[ci], clusters[cj]
        if any(has_hard_conflict(features[u], features[v]) for u in members_i for v in members_j):
            continue
        if _has_competing_candidate(ci, cj, sc) or _has_competing_candidate(cj, ci, sc):
            continue
        for v in members_j:
            owner[v] = ci
        members_i.extend(members_j)
        del clusters[cj]

    # Assign deterministic, collision-checked pseudonyms using canonical cluster key
    result: dict[int, str | None] = {}
    used_psns: set[str] = set()
    # Sort clusters by canonical key for deterministic collision resolution
    canonical_clusters: list[tuple[str, list[int]]] = []
    for members in clusters.values():
        sigs = sorted(features[m].canonical_signature() for m in members)
        canonical_clusters.append(("||".join(sigs), members))
    canonical_clusters.sort(key=lambda x: x[0])

    for c_key, members in canonical_clusters:
        # Only assign pseudonym if at least one member has an identity anchor;
        # singletons without strong ID or name stay null.
        has_anchor = any(
            features[m].strong_ids or features[m].scoped_mrns or features[m].name_tokens
            for m in members
        )
        if not has_anchor:
            for m in members:
                result[m] = None
            continue
        suffix = 0
        while True:
            key_str = c_key if suffix == 0 else f"{c_key}#{suffix}"
            psn = derive_pseudonym(key_str, secret)
            if psn not in used_psns:
                used_psns.add(psn)
                break
            suffix += 1
        for m in members:
            result[m] = psn

    return result
