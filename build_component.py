"""Membangun whisperguard_component_v2.py: satu berkas mandiri untuk ditempel ke Custom Component Langflow.

Sumber: auditor.py (lapisan aturan) + hybrid.py (lapisan LLM) + component_part.py (kelas komponen Langflow).
Jalankan setelah mengubah salah satu sumber:  python build_component.py
"""
aud = open("auditor.py", encoding="utf-8").read().split('if __name__ == "__main__":')[0].rstrip() + "\n"

hyb = open("hybrid.py", encoding="utf-8").read().replace("from auditor import audit_tool, AuditResult\n", "")
start = hyb.index('"""')
end = hyb.index('"""', start + 3) + 3
hyb = hyb[end:].lstrip("\n")  # buang docstring modul

comp = open("component_part.py", encoding="utf-8").read()

open("whisperguard_component_v2.py", "w", encoding="utf-8").write(aud + "\n\n" + hyb.rstrip() + "\n\n\n" + comp)
print("OK: whisperguard_component_v2.py dibangun")
