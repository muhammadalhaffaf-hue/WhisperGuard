"""
WhisperGuard Console - kelola akun dari baris perintah.

Akun admin pertama SENGAJA hanya bisa dibuat dari sini (butuh akses ke komputer server),
bukan dari halaman web yang terbuka. Password diketik lewat getpass dan tidak pernah ditampilkan
atau dicatat.

Contoh:
    python manage_users.py create-admin                 # admin pertama (organisasi dibuat jika belum ada)
    python manage_users.py create-admin --org "Tim B"   # admin untuk organisasi lain
    python manage_users.py create-org "Tim B"
    python manage_users.py list
    python manage_users.py reset-password budi          # password sementara, wajib diganti saat login

Lokasi database: --db, atau variabel WG_DB_PATH, atau console_data.db.
"""
import argparse
import getpass
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

import console_auth as auth
import console_core as core


def ask_password(prompt="Password"):
    while True:
        pw = getpass.getpass(f"{prompt} (min. {auth.MIN_PASSWORD_LEN} karakter): ")
        errors = auth.validate_password(pw)
        if errors:
            print("  " + " ".join(errors))
            continue
        if getpass.getpass("Ulangi password: ") != pw:
            print("  Password tidak sama. Coba lagi.")
            continue
        return pw


def ask(prompt, default=""):
    value = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return value or default


def resolve_org(db, org_name):
    orgs = auth.list_organizations(db)
    if org_name:
        for o in orgs:
            if o["name"].lower() == org_name.strip().lower():
                return o["id"], o["name"]
        return auth.create_organization(db, org_name), org_name.strip()
    if orgs:
        return orgs[0]["id"], orgs[0]["name"]
    name = ask("Nama organisasi", core.DEFAULT_ORG_NAME)
    return auth.create_organization(db, name), name


def cmd_create_admin(args):
    org_id, org_name = resolve_org(args.db, args.org)
    print(f"Membuat admin untuk organisasi: {org_name}")
    username = args.username or ask("Username")
    display = args.name or ask("Nama tampilan", username)
    password = ask_password()
    uid = auth.create_user_cli(args.db, org_id, username, display, "admin", password, must_change=False)
    print(f"Admin '{username}' dibuat (id {uid}). Masuk lewat Console: streamlit run console_app.py")


def cmd_create_org(args):
    oid = auth.create_organization(args.db, args.name)
    print(f"Organisasi '{args.name}' dibuat (id {oid}). Buat admin-nya: "
          f"python manage_users.py create-admin --org \"{args.name}\"")


def cmd_list(args):
    with core.connect(args.db) as con:
        rows = con.execute("SELECT u.id, o.name AS org, u.username, u.display_name, u.role, u.active, "
                           "u.must_change_password FROM users u JOIN organizations o ON o.id = u.org_id "
                           "ORDER BY o.id, u.id").fetchall()
    if not rows:
        print("Belum ada akun. Jalankan: python manage_users.py create-admin")
        return
    for r in rows:
        flags = ("aktif" if r["active"] else "NONAKTIF") + (", wajib ganti password" if r["must_change_password"] else "")
        print(f"#{r['id']:<3} {r['org']:<24} {r['username']:<20} {r['role']:<10} {flags}  ({r['display_name']})")


def cmd_reset_password(args):
    print(f"Password sementara untuk '{args.username}'. Akun dibuka kuncinya, diaktifkan, "
          "dan wajib ganti password saat login.")
    auth.reset_password_cli(args.db, args.username, ask_password("Password sementara"))
    print("Selesai.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Kelola akun WhisperGuard Console.")
    p.add_argument("--db", default=core.env("WG_DB_PATH", "console_data.db"), help="lokasi database SQLite")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin", help="buat akun admin (admin pertama dibuat di sini)")
    a.add_argument("--org", help="nama organisasi (dibuat jika belum ada)")
    a.add_argument("--username")
    a.add_argument("--name", help="nama tampilan")
    a.set_defaults(func=cmd_create_admin)
    o = sub.add_parser("create-org", help="buat organisasi baru")
    o.add_argument("name")
    o.set_defaults(func=cmd_create_org)
    sub.add_parser("list", help="daftar semua akun").set_defaults(func=cmd_list)
    r = sub.add_parser("reset-password", help="beri password sementara (pemulihan)")
    r.add_argument("username")
    r.set_defaults(func=cmd_reset_password)
    args = p.parse_args(argv)
    try:
        args.func(args)
    except auth.AccountError as e:
        print(f"Gagal: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nDibatalkan.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
