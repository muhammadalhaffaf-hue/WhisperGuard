"""Tes sinkronisasi: kode yang diukur (auditor.py, hybrid.py) = kode yang terpasang di Langflow.

Gagal jika:
1. Berkas komponen berbeda dari hasil build_component.py (lupa build ulang, atau komponen diedit langsung).
2. Aturan di auditor.py (ID, kategori, bobot, regex) berbeda dari aturan di komponen.
3. Hasil audit_tool / audit_hybrid berbeda antara sumber modular dan komponen pada semua kasus eval.

Jalankan: python test_sync.py
"""
import json
import os

import auditor
import build_component
import hybrid
from component_harness import FakeLLM, load, run
from eval import CLEAN, POISONED
from eval_v2 import GROUPS

HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT_PATH = os.path.join(HERE, build_component.OUTPUT)


def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label)
    assert cond, label


def rule_table(mod):
    rules = [(rid, cat, w, rx.pattern, rx.flags, expl) for rid, cat, w, rx, expl in mod.ATTACK_RULES]
    return {
        "attack_rules": rules,
        "invisible": mod.CHECK_INVISIBLE,
        "approved_verbs": sorted(mod.APPROVED_VERBS),
        "read_only_prefix": mod.READ_ONLY_PREFIX,
        "write_actions": (mod.WRITE_ACTIONS.pattern, mod.WRITE_ACTIONS.flags),
    }


# 1. Berkas komponen = hasil build
with open(COMPONENT_PATH, encoding="utf-8", newline="") as f:
    installed = f.read().replace("\r\n", "\n")
check(f"{build_component.OUTPUT} identik dengan hasil build (jalankan: python build_component.py)",
      build_component.build().rstrip("\n") == installed.rstrip("\n"))

comp = load(COMPONENT_PATH, "wg_component")

# 2. Tabel aturan sama
mine, theirs = rule_table(auditor), rule_table(comp)
for key in mine:
    check(f"aturan '{key}' sama di auditor.py dan komponen", mine[key] == theirs[key])
for name in ("SYSTEM_PROMPT", "USER_TEMPLATE", "VERDICT_SCORE", "RECOMMENDATIONS", "ATTACK_IDS", "GOV_IDS"):
    check(f"hybrid.{name} sama dengan komponen", getattr(hybrid, name) == getattr(comp, name))

# 3. Hasil audit sama pada semua kasus eval
cases = list(CLEAN) + list(POISONED) + [c for _, cs, _ in GROUPS for c in cs]
diff = [n for n, d in cases if auditor.audit_tool(n, d).to_dict() != comp.audit_tool(n, d).to_dict()]
check(f"audit_tool identik pada {len(cases)} kasus eval" + (f" (beda: {diff})" if diff else ""), not diff)

replies = [
    json.dumps({"verdict": "malicious", "confidence": 0.9, "categories": ["exfiltration"],
                "evidence": ["Before"], "reasoning": "uji"}),
    json.dumps({"verdict": "safe", "confidence": 0.9, "categories": [], "evidence": [], "reasoning": "uji"}),
    "bukan json",
]
diff = []
for reply in replies:
    for n, d in cases:
        a = hybrid.audit_hybrid(n, d, llm_fn=lambda s, u: reply)
        b = comp.audit_hybrid(n, d, llm_fn=lambda s, u: reply)
        if (a.to_dict(), a.layer1_score, a.needs_human_review) != (b.to_dict(), b.layer1_score, b.needs_human_review):
            diff.append(n)
check(f"audit_hybrid identik pada {len(cases)} kasus x {len(replies)} balasan LLM tiruan", not diff)

# Jejak Console (mode lokal) memakai build_trace yang sama dengan komponen.
import console_core  # noqa: E402

n, d = POISONED[0]
local = [s["step"] for s in console_core.audit_local(n, d)["trace"]]
component = [s["step"] for s in run(comp, n, d)["trace"]]
check("Console mode lokal: urutan jejak sama dengan komponen", local == component)

print("\nSemua tes sinkronisasi lolos.")
