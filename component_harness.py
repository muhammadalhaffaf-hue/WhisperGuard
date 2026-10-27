"""Menjalankan komponen Langflow WhisperGuard tanpa Langflow: modul langflow/langchain ditiru.

Dipakai oleh tes (test_component.py, test_sync.py, test_sanitization.py) dan eval_v3.py --dry-run.
Mengimpor berkas ini memasang modul tiruan di sys.modules.
"""
import importlib.util
import sys
import types


class _Component:
    pass


class _Input:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Data:
    def __init__(self, data):
        self.data = data


class _Msg:
    def __init__(self, content):
        self.content = content


for _mod, _attrs in {
    "langflow": {}, "langflow.custom": {"Component": _Component},
    "langflow.io": {"HandleInput": _Input, "MessageTextInput": _Input, "Output": _Input},
    "langflow.schema": {"Data": _Data},
    "langchain_core": {}, "langchain_core.messages": {"HumanMessage": _Msg, "SystemMessage": _Msg},
}.items():
    if _mod not in sys.modules:
        _m = types.ModuleType(_mod)
        _m.__dict__.update(_attrs)
        sys.modules[_mod] = _m


def load(path, name):
    """Muat berkas komponen sebagai modul."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeLLM:
    """LLM tiruan. reply: teks balasan tetap, atau fungsi (messages) -> teks. fail: lempar TimeoutError."""

    def __init__(self, reply, fail=False):
        self.reply, self.fail = reply, fail

    def invoke(self, messages):
        if self.fail:
            raise TimeoutError("simulasi")
        return _Msg(self.reply(messages) if callable(self.reply) else self.reply)


def run(mod, name, desc, llm=None, via_request=False):
    """Jalankan WhisperGuardAudit.run_audit() dan kembalikan payload dict."""
    c = mod.WhisperGuardAudit()
    c.tool_name, c.tool_description, c.audit_request = name, desc, ""
    if via_request:
        c.tool_name = c.tool_description = ""
        c.audit_request = f"tool_name: {name}\ntool_description: {desc}"
    c.llm = llm
    return c.run_audit().data
