"""
WhisperGuard Console - akun lokal, sesi, dan log aktivitas (tanpa tampilan).

Prinsip:
- Password tidak pernah disimpan atau dicatat dalam bentuk asli. Yang disimpan hanya hasil
  hashlib.scrypt dengan salt acak per akun; pembandingan memakai hmac.compare_digest.
- Pesan gagal login selalu sama, apa pun penyebabnya (user tidak ada, password salah, akun nonaktif,
  akun terkunci), supaya tidak membocorkan akun mana yang ada.
- 5 kali gagal berturut-turut mengunci akun selama 5 menit.
- Password sementara (dibuat admin) wajib diganti saat login pertama.
- Semua aksi admin diperiksa di sini, bukan hanya disembunyikan di tampilan.
"""
import hashlib
import hmac
import secrets
import time

import console_core as core
from console_core import AccessDenied

MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 256  # batas atas supaya scrypt tidak dipakai untuk membebani server
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60
SESSION_TIMEOUT_SECONDS = 30 * 60

LOGIN_FAILED_MESSAGE = ("Username atau password salah, atau akun sedang dikunci sementara. "
                        "Periksa lagi, atau coba beberapa menit lagi.")

# Parameter scrypt (sekitar 16 MB memori per hash). Disimpan bersama hash supaya bisa dinaikkan nanti.
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2 ** 14, 8, 1, 32

# Hash pengganti untuk username yang tidak ada: tetap menjalankan scrypt supaya waktu respons serupa.
_DUMMY_HASH = None

EVENT_LABEL = {
    "login_berhasil": "Login berhasil",
    "login_gagal": "Login gagal",
    "logout": "Logout",
    "logout_otomatis": "Logout otomatis (30 menit tidak aktif)",
    "akun_dibuat": "Akun dibuat",
    "akun_dinonaktifkan": "Akun dinonaktifkan",
    "akun_diaktifkan": "Akun diaktifkan",
    "reset_password": "Password direset",
    "password_diganti": "Password diganti",
    "organisasi_dibuat": "Organisasi dibuat",
}


class AccountError(ValueError):
    """Input akun tidak valid (password terlalu pendek, username terpakai, dan sejenisnya)."""


# ------------------------------------------------------------------ password
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        dklen=SCRYPT_DKLEN, maxmem=64 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, dk_hex = stored.split("$")
        if algo != "scrypt":
            return False
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r),
                            p=int(p), dklen=len(expected), maxmem=64 * 1024 * 1024)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def _dummy_hash():
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    return _DUMMY_HASH


def validate_password(password, username=""):
    """Kembalikan daftar pesan kesalahan untuk password baru."""
    errors = []
    password = password or ""
    if len(password) < MIN_PASSWORD_LEN:
        errors.append(f"Password minimal {MIN_PASSWORD_LEN} karakter.")
    if len(password) > MAX_PASSWORD_LEN:
        errors.append(f"Password maksimal {MAX_PASSWORD_LEN} karakter.")
    if username and password.strip().lower() == username.strip().lower():
        errors.append("Password tidak boleh sama dengan username.")
    return errors


def _clean_username(username) -> str:
    return (username or "").strip()


def _validate_username(username):
    u = _clean_username(username)
    if not (3 <= len(u) <= 40) or not all(ch.isalnum() or ch in "._-" for ch in u):
        raise AccountError("Username 3-40 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.")
    return u


# ------------------------------------------------------------------ log aktivitas
def log_event(con, event, org_id=None, actor_user_id=None, target_user_id=None, username="", detail=""):
    """Catat aktivitas akun. Jangan pernah mengirim password ke fungsi ini."""
    con.execute("INSERT INTO activity_log (created_utc, org_id, actor_user_id, target_user_id, username, "
                "event, detail) VALUES (?,?,?,?,?,?,?)",
                (core.now_utc(), org_id, actor_user_id, target_user_id, core.neutralize(username, 64),
                 event, core.neutralize(detail, 200)))


def load_activity(db_path, actor, limit=300):
    """Log aktivitas organisasi akun. Hanya admin."""
    with core.connect(db_path) as con:
        me = core.resolve_actor(con, actor, "manage_users")
        rows = con.execute(
            "SELECT l.created_utc, l.event, l.username, l.detail, "
            "(SELECT u.display_name FROM users u WHERE u.id = l.actor_user_id) AS actor_name "
            "FROM activity_log l WHERE l.org_id = ? ORDER BY l.id DESC LIMIT ?",
            (me["org_id"], int(limit))).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ organisasi (CLI)
def create_organization(db_path, name) -> int:
    name = core.neutralize(name, 80)
    if not name:
        raise AccountError("Nama organisasi wajib diisi.")
    with core.connect(db_path) as con:
        if con.execute("SELECT 1 FROM organizations WHERE name = ?", (name,)).fetchone():
            raise AccountError("Nama organisasi sudah dipakai.")
        org_id = con.execute("INSERT INTO organizations (name, created_utc) VALUES (?, ?)",
                             (name, core.now_utc())).lastrowid
        log_event(con, "organisasi_dibuat", org_id=org_id, detail=name)
    return org_id


def list_organizations(db_path):
    with core.connect(db_path) as con:
        return [dict(r) for r in con.execute("SELECT id, name, created_utc FROM organizations ORDER BY id")]


def count_users(db_path) -> int:
    with core.connect(db_path) as con:
        return con.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# ------------------------------------------------------------------ pembuatan akun
def _insert_user(con, org_id, username, display_name, role, password, must_change):
    username = _validate_username(username)
    display_name = core.neutralize(display_name, 60)
    if not display_name:
        raise AccountError("Nama tampilan wajib diisi.")
    if role not in core.ROLES:
        raise AccountError("Peran tidak dikenal.")
    errors = validate_password(password, username)
    if errors:
        raise AccountError(" ".join(errors))
    if not con.execute("SELECT 1 FROM organizations WHERE id = ?", (org_id,)).fetchone():
        raise AccountError("Organisasi tidak ditemukan.")
    if con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise AccountError("Username sudah dipakai.")
    return con.execute(
        "INSERT INTO users (org_id, username, display_name, role, active, password_hash, must_change_password, "
        "created_utc) VALUES (?,?,?,?,1,?,?,?)",
        (org_id, username, display_name, role, hash_password(password), int(must_change), core.now_utc())).lastrowid


def create_user_cli(db_path, org_id, username, display_name, role, password, must_change=False) -> int:
    """Hanya untuk manage_users.py (akses langsung ke server). Tidak ada halaman web untuk ini."""
    with core.connect(db_path) as con:
        uid = _insert_user(con, org_id, username, display_name, role, password, must_change)
        log_event(con, "akun_dibuat", org_id=org_id, target_user_id=uid, username=username,
                  detail=f"peran {role}; lewat baris perintah")
    return uid


def create_user(db_path, actor, username, display_name, role, temp_password) -> int:
    """Admin membuat akun di organisasinya sendiri. Password sementara wajib diganti saat login pertama."""
    with core.connect(db_path) as con:
        me = core.resolve_actor(con, actor, "manage_users")
        uid = _insert_user(con, me["org_id"], username, display_name, role, temp_password, must_change=True)
        log_event(con, "akun_dibuat", org_id=me["org_id"], actor_user_id=me["id"], target_user_id=uid,
                  username=_clean_username(username), detail=f"peran {role}")
    return uid


def list_users(db_path, actor, now=None):
    now = time.time() if now is None else now
    with core.connect(db_path) as con:
        me = core.resolve_actor(con, actor, "manage_users")
        rows = con.execute("SELECT id, username, display_name, role, active, must_change_password, "
                           "locked_until, created_utc, last_login_utc FROM users WHERE org_id = ? ORDER BY id",
                           (me["org_id"],)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["locked"] = d.pop("locked_until") > now
        out.append(d)
    return out


def _target_in_org(con, me, user_id):
    row = con.execute("SELECT * FROM users WHERE id = ? AND org_id = ?", (user_id, me["org_id"])).fetchone()
    if row is None:
        raise AccessDenied("Akun tidak ditemukan.")
    return row


def set_active(db_path, actor, user_id, active: bool):
    """Aktifkan atau nonaktifkan akun di organisasi yang sama. Admin tidak bisa menonaktifkan dirinya
    sendiri atau admin aktif terakhir di organisasinya."""
    with core.connect(db_path) as con:
        me = core.resolve_actor(con, actor, "manage_users")
        target = _target_in_org(con, me, user_id)
        if not active:
            if target["id"] == me["id"]:
                raise AccountError("Kamu tidak bisa menonaktifkan akunmu sendiri.")
            if target["role"] == "admin" and target["active"]:
                admins = con.execute("SELECT COUNT(*) FROM users WHERE org_id = ? AND role = 'admin' AND active = 1",
                                     (me["org_id"],)).fetchone()[0]
                if admins <= 1:
                    raise AccountError("Admin aktif terakhir tidak bisa dinonaktifkan.")
        con.execute("UPDATE users SET active = ? WHERE id = ?", (int(bool(active)), target["id"]))
        log_event(con, "akun_diaktifkan" if active else "akun_dinonaktifkan", org_id=me["org_id"],
                  actor_user_id=me["id"], target_user_id=target["id"], username=target["username"])


def reset_password(db_path, actor, user_id, temp_password):
    """Admin memberi password sementara. Akun dibuka kuncinya dan wajib ganti password saat login."""
    with core.connect(db_path) as con:
        me = core.resolve_actor(con, actor, "manage_users")
        target = _target_in_org(con, me, user_id)
        errors = validate_password(temp_password, target["username"])
        if errors:
            raise AccountError(" ".join(errors))
        con.execute("UPDATE users SET password_hash = ?, must_change_password = 1, failed_attempts = 0, "
                    "locked_until = 0 WHERE id = ?", (hash_password(temp_password), target["id"]))
        log_event(con, "reset_password", org_id=me["org_id"], actor_user_id=me["id"],
                  target_user_id=target["id"], username=target["username"])


def reset_password_cli(db_path, username, temp_password):
    """Pemulihan lewat baris perintah (misalnya admin terakhir lupa password)."""
    with core.connect(db_path) as con:
        target = con.execute("SELECT * FROM users WHERE username = ?", (_clean_username(username),)).fetchone()
        if target is None:
            raise AccountError("Akun tidak ditemukan.")
        errors = validate_password(temp_password, target["username"])
        if errors:
            raise AccountError(" ".join(errors))
        con.execute("UPDATE users SET password_hash = ?, must_change_password = 1, failed_attempts = 0, "
                    "locked_until = 0, active = 1 WHERE id = ?", (hash_password(temp_password), target["id"]))
        log_event(con, "reset_password", org_id=target["org_id"], target_user_id=target["id"],
                  username=target["username"], detail="lewat baris perintah")


# ------------------------------------------------------------------ login dan sesi
def _session_user(row):
    return {"id": row["id"], "org_id": row["org_id"], "username": row["username"],
            "display_name": row["display_name"], "role": row["role"],
            "must_change_password": bool(row["must_change_password"])}


def authenticate(db_path, username, password, now=None):
    """Kembalikan (akun, None) jika berhasil, atau (None, pesan_generik) jika gagal."""
    now = time.time() if now is None else now
    username = _clean_username(username)
    password = password or ""
    with core.connect(db_path) as con:
        too_long = len(password) > MAX_PASSWORD_LEN
        password = password[:MAX_PASSWORD_LEN]
        row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() if username else None
        if row is None:
            verify_password(password, _dummy_hash())  # samakan waktu respons dengan akun yang ada
            log_event(con, "login_gagal", username=username, detail="akun tidak dikenal")
            return None, LOGIN_FAILED_MESSAGE
        if row["locked_until"] > now:
            verify_password(password, _dummy_hash())
            log_event(con, "login_gagal", org_id=row["org_id"], target_user_id=row["id"], username=row["username"],
                      detail="akun sedang dikunci")
            return None, LOGIN_FAILED_MESSAGE
        ok = verify_password(password, row["password_hash"]) and not too_long
        if ok and row["active"]:
            con.execute("UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_utc = ? WHERE id = ?",
                        (core.now_utc(), row["id"]))
            log_event(con, "login_berhasil", org_id=row["org_id"], actor_user_id=row["id"],
                      target_user_id=row["id"], username=row["username"])
            return _session_user(row), None
        if not row["active"]:
            log_event(con, "login_gagal", org_id=row["org_id"], target_user_id=row["id"], username=row["username"],
                      detail="akun nonaktif")
            return None, LOGIN_FAILED_MESSAGE
        failed = row["failed_attempts"] + 1
        if failed >= MAX_FAILED_ATTEMPTS:
            con.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                        (now + LOCKOUT_SECONDS, row["id"]))
            detail = f"password salah; akun dikunci {LOCKOUT_SECONDS // 60} menit"
        else:
            con.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, row["id"]))
            detail = f"password salah ({failed}/{MAX_FAILED_ATTEMPTS})"
        log_event(con, "login_gagal", org_id=row["org_id"], target_user_id=row["id"], username=row["username"],
                  detail=detail)
        return None, LOGIN_FAILED_MESSAGE


def refresh_session(db_path, user_id):
    """Baca ulang akun untuk sesi yang sedang terbuka. None jika akun hilang atau nonaktif."""
    with core.connect(db_path) as con:
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None or not row["active"]:
        return None
    return _session_user(row)


def change_own_password(db_path, user_id, old_password, new_password):
    """Ganti password sendiri. Dipakai juga untuk mengganti password sementara saat login pertama."""
    with core.connect(db_path) as con:
        row = con.execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()
        if row is None:
            raise AccessDenied("Sesi tidak berlaku. Silakan masuk lagi.")
        if not verify_password(old_password or "", row["password_hash"]):
            raise AccountError("Password lama salah.")
        errors = validate_password(new_password, row["username"])
        if hmac.compare_digest((old_password or "").encode("utf-8"), (new_password or "").encode("utf-8")):
            errors.append("Password baru harus berbeda dari password lama.")
        if errors:
            raise AccountError(" ".join(errors))
        con.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                    (hash_password(new_password), row["id"]))
        log_event(con, "password_diganti", org_id=row["org_id"], actor_user_id=row["id"],
                  target_user_id=row["id"], username=row["username"])


def record_logout(db_path, user, automatic=False):
    if not user:
        return
    with core.connect(db_path) as con:
        log_event(con, "logout_otomatis" if automatic else "logout", org_id=user.get("org_id"),
                  actor_user_id=user.get("id"), target_user_id=user.get("id"), username=user.get("username", ""))


def session_expired(last_activity, now=None, timeout=SESSION_TIMEOUT_SECONDS) -> bool:
    now = time.time() if now is None else now
    return last_activity is None or (now - last_activity) > timeout
