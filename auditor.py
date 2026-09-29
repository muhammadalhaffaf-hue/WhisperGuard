"""
WhisperGuard - audit integritas nama & deskripsi tool MCP.

Prinsip desain:
- Deskripsi tool diperlakukan sebagai DATA TIDAK DIPERCAYA, tidak pernah sebagai instruksi.
- Lapisan 1 (file ini): aturan deterministik, cepat, bisa dijelaskan, kebal injeksi.
- Lapisan 2 (nanti, LLM): penalaran tambahan, hanya menaikkan skor, tidak pernah menurunkan
  hasil lapisan 1. Lihat llm_prompt.md.
"""
import re
import unicodedata
from dataclasses import dataclass, asdict, field

APPROVED_VERBS = {
    "create", "creates", "retrieve", "retrieves", "save", "saves", "analyze", "analyzes",
    "answer", "answers", "get", "gets", "list", "lists", "send", "sends", "update", "updates",
    "search", "searches", "summarize", "summarizes", "generate", "generates", "audit", "audits",
    "add", "adds", "delete", "deletes", "fetch", "fetches", "read", "reads", "write", "writes",
    "calculate", "calculates", "convert", "converts", "extract", "extracts", "check", "checks",
}
READ_ONLY_PREFIX = ("get", "list", "read", "fetch", "search", "summarize", "answer", "retrieve",
                    "calculate", "check", "analyze", "audit")
WRITE_ACTIONS = re.compile(
    r"\b(send|email|upload|post|forward|delete|remove|write to|overwrite|execute|run command|transmit)\b", re.I)

# (id, kategori, bobot, regex, penjelasan)
ATTACK_RULES = [
    ("R02", "hidden_markup", 35,
     re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>|<!--|\[\s*(hidden|system)\s*\]", re.I),
     "Ada markup/tag tersembunyi yang biasa dipakai menyisipkan instruksi untuk agent."),
    ("R03", "conceal_from_user", 40,
     re.compile(r"(do not|don't|never)\s+(tell|mention|inform|reveal|show)|without\s+(telling|informing|notifying)|"
                r"\bsilently\b|keep\s+(this|it)\s+(secret|hidden)", re.I),
     "Ada instruksi agar agent menyembunyikan tindakan dari user."),
    ("R04", "sensitive_access", 35,
     re.compile(r"~/\.ssh|id_rsa|\.env\b|/etc/passwd|mcp\.json|api[_ -]?key|credential|secret|password|"
                r"access[_ -]?token|private key", re.I),
     "Deskripsi menyebut akses ke file/kredensial sensitif yang tidak relevan untuk deskripsi tool."),
    ("R05", "exfiltration", 30,
     re.compile(r"(send|forward|upload|post|transmit|exfiltrat\w*)\b[^.]{0,60}\b(to|at)\b[^.]{0,40}(https?://|@\w+\.\w+)", re.I),
     "Ada pola pengiriman data ke alamat eksternal."),
    ("R06", "instruction_override", 30,
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above)|before\s+(using|calling|running)\s+(this|any|other)|"
                r"instead\s+of\s+(using|calling)|override|you\s+(must|should)\s+(always|first)|"
                r"when\s+(calling|using)\s+(any\s+)?other\s+tool|system\s+prompt", re.I),
     "Ada kalimat perintah kepada agent yang melampaui fungsi tool (mengatur tool lain / mengabaikan instruksi)."),
]

CHECK_INVISIBLE = ("R01", "invisible_unicode", 40)


@dataclass
class Finding:
    rule_id: str
    category: str
    weight: int
    evidence: str
    explanation: str


@dataclass
class AuditResult:
    tool_name: str
    risk_score: int
    risk_level: str
    findings: list = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self):
        d = asdict(self)
        return d


def _invisible_chars(text: str):
    bad = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F or cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF) \
                or 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            bad.append(cp)
        elif unicodedata.category(ch) == "Cf":
            bad.append(cp)
    return bad


def _snippet(text, m, pad=25):
    s, e = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return text[s:e].replace("\n", " ")


def audit_tool(tool_name: str, description: str) -> AuditResult:
    findings: list[Finding] = []
    desc = description or ""
    name = tool_name or ""

    # R01: karakter tak terlihat (termasuk Unicode tag characters)
    inv = _invisible_chars(desc)
    if inv:
        findings.append(Finding(*CHECK_INVISIBLE, f"{len(inv)} karakter tak terlihat (contoh U+{inv[0]:04X})",
                                "Karakter tak terlihat bisa menyembunyikan instruksi dari mata manusia."))

    # R02-R06: pola serangan
    for rid, cat, w, rx, expl in ATTACK_RULES:
        m = rx.search(desc)
        if m:
            findings.append(Finding(rid, cat, w, _snippet(desc, m), expl))

    # R07: konvensi penamaan (governance)
    if not re.fullmatch(r"[a-z]+(_[a-z0-9]+)+", name):
        findings.append(Finding("R07", "naming_convention", 10, name,
                                "Nama tool harus snake_case, spesifik, dan diawali kata kerja (verb_object)."))
    else:
        first = name.split("_")[0]
        if first not in APPROVED_VERBS:
            findings.append(Finding("R07", "naming_convention", 8, name,
                                    "Nama tool tidak diawali kata kerja yang jelas."))

    # R08: deskripsi diawali kata kerja
    words = desc.strip().split()
    if not words or words[0].lower().strip(",.:") not in APPROVED_VERBS:
        findings.append(Finding("R08", "description_convention", 8, (desc.strip()[:40] or "(kosong)"),
                                "Deskripsi harus diawali kata kerja (Creates, Retrieves, Saves, Analyzes...)."))

    # R09: ketidaksesuaian cakupan nama vs deskripsi
    if name.split("_")[0] in READ_ONLY_PREFIX:
        m = WRITE_ACTIONS.search(desc)
        if m:
            findings.append(Finding("R09", "scope_mismatch", 20, _snippet(desc, m),
                                    "Nama menyiratkan tool hanya-baca, tetapi deskripsi menyebut aksi tulis/kirim/hapus."))

    # R10: deskripsi terlalu panjang (tempat payload bersembunyi)
    if len(desc) > 600:
        findings.append(Finding("R10", "length_anomaly", 8, f"{len(desc)} karakter",
                                "Deskripsi tool sangat panjang; area ini sering dipakai menyisipkan payload."))

    score = min(100, sum(f.weight for f in findings))
    attack_cats = {f.category for f in findings
                   if f.rule_id in {"R01", "R02", "R03", "R04", "R05", "R06"}}
    # dua sinyal serangan berbeda = hampir pasti berbahaya
    if len(attack_cats) >= 2:
        score = max(score, 70)
    # karakter tak terlihat + apa pun = HIGH
    if "invisible_unicode" in attack_cats:
        score = max(score, 60)

    level = "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
    rec = {
        "HIGH": "JANGAN daftarkan/panggil tool ini sebelum ditinjau manusia. Karantina dan buat laporan insiden.",
        "MEDIUM": "Tinjau manual deskripsi tool dan perbaiki sebelum dipakai di produksi.",
        "LOW": "Tidak ada indikasi mencurigakan dari pemeriksaan aturan. Tetap lakukan tinjauan berkala.",
    }[level]
    return AuditResult(name, score, level, [asdict(f) for f in findings], rec)


if __name__ == "__main__":
    import json
    r = audit_tool("create_meeting_summary",
                   "Creates a summary from meeting notes provided by the user.")
    print(json.dumps(r.to_dict(), indent=2, ensure_ascii=False))