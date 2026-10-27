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
APPROVED_VERBS |= {
    # kata dasar (untuk nama tool)
    "ambil", "hitung", "cari", "ubah", "terjemahkan", "baca", "kirim", "buat", "simpan", "hapus",
    "tampilkan", "periksa", "cek", "ringkas", "perbarui", "tambah", "ekspor", "impor", "unduh", "unggah",
    "analisis", "susun", "catat", "daftar", "konversi", "ekstrak", "ubah",
    # bentuk meN- (untuk awal deskripsi)
    "mengambil", "menghitung", "mencari", "mengubah", "menerjemahkan", "membaca", "mengirim", "membuat",
    "menyimpan", "menghapus", "menampilkan", "memeriksa", "merangkum", "memperbarui", "menambah",
    "mengekspor", "mengimpor", "mengunduh", "mengunggah", "menganalisis", "menyusun", "mencatat",
    "mengonversi", "mengekstrak", "mengecek",
}
WRITE_ACTIONS = re.compile(
    r"\b(send|upload|post|forward|delete|remove|write to|overwrite|execute|run command|transmit)\b", re.I)

# (id, kategori, bobot, regex, penjelasan)
ATTACK_RULES = [
    ("R02", "hidden_markup", 35,
     re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>|<!--|\[\s*(hidden|system)\s*\]", re.I),
     "Ada markup/tag tersembunyi yang biasa dipakai menyisipkan instruksi untuk agent."),
    ("R03", "conceal_from_user", 40,
     re.compile(r"(do not|don't|never)\s+(tell|mention|inform|reveal|show)|without\s+(telling|informing|notifying)|"
                r"\bsilently\b|keep\s+(this|it)\s+(secret|hidden)|"
                r"jangan\s+(beri\s?tahu|katakan|sampaikan|beritahu)", re.I),
     "Ada instruksi agar agent menyembunyikan tindakan dari user."),
    # Sensitif KUAT: path/file kredensial spesifik. Sensitif LEMAH ada di R04w (bobot kecil).
    ("R04", "sensitive_access", 35,
     re.compile(r"~/\.ssh|~/\.aws|id_rsa|\.env\b|/etc/passwd|mcp\.json|credentials?\s+file|"
                r"private key|/\.config/|\.netrc", re.I),
     "Deskripsi menyebut akses ke file/kredensial sensitif yang tidak relevan untuk deskripsi tool."),
    ("R04w", "sensitive_access", 12,
     re.compile(r"api[_ -]?key|credential|secret|password|access[_ -]?token", re.I),
     "Deskripsi menyebut istilah kredensial. Wajar untuk tool tertentu, perlu konteks."),
    ("R05", "exfiltration", 30,
     re.compile(r"(send|forward|upload|post|transmit|exfiltrat\w*|kirim)\b[^.]{0,60}\b(to|at|ke)\b[^.]{0,40}(https?://|@\w+\.\w+)", re.I),
     "Ada pola pengiriman data ke alamat eksternal."),
    ("R06", "instruction_override", 30,
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above)|before\s+(using|calling|running)\s+(this|any|other)|"
                r"instead\s+of\s+(using|calling)|override|you\s+(must|should)\s+(always|first)|"
                r"when\s+(calling|using)\s+(any\s+)?other\s+tool|system\s+prompt|"
                r"note\s+to\s+(the\s+)?(assistant|model|agent)|"
                r"the\s+(assistant|model|agent)\s+(needs|must|should)|"
                r"replaces\s+the\s+(built-in\s+)?\w+|routed?\s+through\s+this\s+tool|"
                r"follow\s+any\s+instructions", re.I),
     "Ada kalimat perintah kepada agent yang melampaui fungsi tool (mengatur tool lain / mengabaikan instruksi)."),
    ("R13", "data_harvest", 25,
     re.compile(r"(always\s+)?(include|pass|add|attach)\b[^.]{0,30}(chat history|conversation|user'?s?\s+(email|location|name|history))", re.I),
     "Deskripsi meminta agent menyertakan data pengguna/percakapan yang tidak dibutuhkan fungsi tool."),
]

CHECK_INVISIBLE = ("R01", "invisible_unicode", 40)

# Tanda kutip tipografis -> ASCII, supaya "user\u2019s" dan "don\u2019t" cocok dengan pola aturan.
# Satu karakter diganti satu karakter: posisi temuan tetap, bukti tetap diambil dari teks asli.
QUOTE_MAP = str.maketrans({"\u2018": "'", "\u2019": "'", "\u02bc": "'", "\u201c": '"', "\u201d": '"'})


def normalize_quotes(text: str) -> str:
    return (text or "").translate(QUOTE_MAP)


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
    scan = normalize_quotes(desc)  # teks untuk pencocokan pola; panjangnya sama dengan desc

    # R01: karakter tak terlihat (termasuk Unicode tag characters)
    inv = _invisible_chars(desc)
    if inv:
        findings.append(Finding(*CHECK_INVISIBLE, f"{len(inv)} karakter tak terlihat (contoh U+{inv[0]:04X})",
                                "Karakter tak terlihat bisa menyembunyikan instruksi dari mata manusia."))

    # R02-R06: pola serangan
    for rid, cat, w, rx, expl in ATTACK_RULES:
        m = rx.search(scan)
        if m:
            findings.append(Finding(rid, cat, w, _snippet(desc, m), expl))

    # R11: blob berkode (base64) yang bisa menyembunyikan payload
    m = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", desc)
    if m:
        findings.append(Finding("R11", "encoded_payload", 40, m.group(0)[:30] + "...",
                                "Ada string panjang terkode (mirip base64) di dalam deskripsi; payload bisa bersembunyi di sini."))

    # R12: kata dengan campuran aksara Latin + Cyrillic/Yunani (homoglyph)
    for tok in re.findall(r"\w+", desc):
        scripts = set()
        for ch in tok:
            if ch.isalpha():
                nm = unicodedata.name(ch, "")
                scripts.add("LATIN" if nm.startswith("LATIN") else "CYRILLIC" if nm.startswith("CYRILLIC")
                            else "GREEK" if nm.startswith("GREEK") else "OTHER")
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            findings.append(Finding("R12", "homoglyph", 40, tok,
                                    "Kata memakai campuran aksara (mis. Latin + Cyrillic) untuk menghindari deteksi kata kunci."))
            break

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
        m = WRITE_ACTIONS.search(scan)
        if m:
            findings.append(Finding("R09", "scope_mismatch", 20, _snippet(desc, m),
                                    "Nama menyiratkan tool hanya-baca, tetapi deskripsi menyebut aksi tulis/kirim/hapus."))

    # R10: deskripsi terlalu panjang (tempat payload bersembunyi)
    if len(desc) > 600:
        findings.append(Finding("R10", "length_anomaly", 8, f"{len(desc)} karakter",
                                "Deskripsi tool sangat panjang; area ini sering dipakai menyisipkan payload."))

    score = min(100, sum(f.weight for f in findings))
    attack_cats = {f.category for f in findings
                   if f.rule_id in {"R01", "R02", "R03", "R04", "R04w", "R05", "R06", "R11", "R12", "R13"}}
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
