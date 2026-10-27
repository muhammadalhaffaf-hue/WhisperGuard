# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Primary: security / IT staff who review MCP tool audits as routine daily work. They paste a tool's server, name, and description, read the risk result and findings, and record a human decision (Setujui / Karantina / Perlu revisi). Developers use IBM Bob as their main path; the Console is the human oversight room.

Secondary: hackathon judges watching a ~2-minute demo (rug-pull scenario). Not the design target.

## Product Purpose
WhisperGuard detects MCP tool poisoning: hidden instructions inside tool names and descriptions that make an agent act against the user. The Console lets humans audit tools manually, see how each audit was decided, catch silently changed ("rug pull") descriptions, and keep an immutable decision log. Success: a reviewer can tell in seconds whether a tool is dangerous, why, and whether it changed since approval, then record a defensible decision.

## Positioning
Two-layer audit (deterministic rules + isolated LLM that can only raise the score, with quoted evidence verified against the original text), plus drift detection against the human-approved baseline. The final decision always stays with a human.

## Operating Context
- Runs locally: `streamlit run console_app.py`, history in local SQLite (`console_data.db`).
- Audit engine: Langflow flow shared with Bob, or local rules fallback (`auditor.py`) flagged "perlu tinjauan manusia".
- Three tabs: Audit, Riwayat (history, filters, CSV export), Keputusan (decision form, immutable trail).
- Execution trace replayed step by step after audit (Graphviz diagram + table with real durations).

## Capabilities and Constraints
- Stack is fixed: Streamlit (`console_app.py`), logic in `console_core.py`. Redesign changes presentation only.
- All UI copy is Indonesian and stays as is.
- Behavior stays identical: decision validation (HIGH or BERUBAH approvals need a 20+ char reason), drift labels BARU / SAMA / BERUBAH, trace replay.
- Tool names and descriptions are untrusted data: render as plain text/code, never as HTML.
- Risk levels: LOW, MEDIUM, HIGH; score 0–100.

## Evidence on Hand
- Built-in examples in `console_app.py` (clean, obvious attack, subtle attack, rug-pull pair).
- Screenshots in `bukti/`. Small self-written eval set (25 clean, 11 attacks); not a large-scale benchmark. Do not claim more.

## Product Principles
1. The human decides; the interface makes the decision informed, never automatic.
2. Untrusted text is shown, never obeyed or rendered.
3. Danger must be unmissable; calm states stay quiet.
4. Show the real mechanism (actual steps, actual durations), not decoration.
5. State limits plainly.
