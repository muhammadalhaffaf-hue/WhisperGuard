---
name: WhisperGuard Console
description: Human oversight room for MCP tool audits, laid out as a clinical lab result sheet.
colors:
  ground: "#eef1f2"
  ground-deep: "#e3e9eb"
  sheet: "#ffffff"
  sheet-tint: "#f5f7f8"
  rule: "#cfd6da"
  rule-soft: "#e6eaec"
  ink: "#20262d"
  ink-2: "#4a5560"
  slate-skip: "#5f6b75"
  teal: "#0f6e74"
  teal-deep: "#0b555a"
  teal-wash: "#d7ebec"
  band-caption: "#d8ecec"
  flag-low: "#1f7a4d"
  flag-med: "#9a6412"
  flag-high: "#b42318"
  range-low: "#cfe5d8"
  range-med: "#f1dfbd"
  range-high: "#f3cdc8"
typography:
  score:
    fontFamily: "Roboto Mono, ui-monospace, Consolas, monospace"
    fontSize: "3.4rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.03em"
    fontFeature: "tnum"
  headline:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "1.45rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "0.98rem"
    fontWeight: 650
  body:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
  table:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "0.88rem"
    fontWeight: 400
  data:
    fontFamily: "Roboto Mono, ui-monospace, Consolas, monospace"
    fontSize: "0.98rem"
    fontWeight: 400
    fontFeature: "tnum"
  label:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "0.74rem"
    fontWeight: 600
    letterSpacing: "0.06em"
  flag:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "0.86rem"
    fontWeight: 700
    letterSpacing: "0.04em"
  scale:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "0.76rem"
    fontWeight: 400
    fontFeature: "tnum"
rounded:
  seg: "2px"
  flag: "3px"
  sheet: "4px"
spacing:
  hair: "2px"
  xs: "6px"
  sm: "10px"
  md: "14px"
  sheet-y: "18px"
  sheet-x: "20px"
  band-x: "22px"
  id-col: "36px"
components:
  button-primary:
    backgroundColor: "{colors.teal}"
    textColor: "{colors.sheet}"
    rounded: "{rounded.sheet}"
  button-primary-hover:
    backgroundColor: "{colors.teal-deep}"
    textColor: "{colors.sheet}"
  header-band:
    backgroundColor: "{colors.teal}"
    textColor: "{colors.sheet}"
    typography: "{typography.headline}"
    rounded: "{rounded.sheet}"
    padding: "16px 22px"
  sheet:
    backgroundColor: "{colors.sheet}"
    rounded: "{rounded.sheet}"
    padding: "18px 20px"
  flag-high:
    backgroundColor: "{colors.flag-high}"
    textColor: "{colors.sheet}"
    typography: "{typography.flag}"
    rounded: "{rounded.flag}"
    padding: "3px 10px"
  flag-med:
    backgroundColor: "{colors.flag-med}"
    textColor: "{colors.sheet}"
    typography: "{typography.flag}"
    rounded: "{rounded.flag}"
    padding: "3px 10px"
  flag-low:
    backgroundColor: "{colors.flag-low}"
    textColor: "{colors.sheet}"
    typography: "{typography.flag}"
    rounded: "{rounded.flag}"
    padding: "3px 10px"
  range-segment:
    backgroundColor: "{colors.range-low}"
    rounded: "{rounded.seg}"
    height: "12px"
  empty-state:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.sheet}"
    padding: "28px 20px"
---

# Design System: WhisperGuard Console

## Overview

**Creative North Star: "The Lab Result Sheet"**

Every audit reads like a clinical lab report. Each one opens with an identity header (which audit, which server, which tool, which engine), then gives a measured value against a printed reference range and flags anything out of range. The reviewer reads it the way a clinician reads bloodwork: find the number, check where it sits in the range, read the flag, then go to the detail lines. The console is a daily work tool used under office light, so it stays dense, calm, and legible. Colour is spent on findings, not on decoration.

The world is paper on a desk. White sheets sit on a cool grey-blue ground, separated by hairline rules instead of shadows. A heavier 2px ink rule closes each sheet's identity header, the way a printed form closes its patient block. Deep teal belongs to the institution: the header band, primary actions, and selection. Red, amber, and green belong to the result. Every number and identifier is set in a monospaced face with tabular figures, so values line up and read as measurements. Prose and labels are set in a plain civic sans.

The world rejects the glassy aurora dashboard and the generic white SaaS card grid. It has no glass, no gradients, and no shadows.

**Key Characteristics:**
- Flat white sheets on a cool grey ground, separated by 1px rules. Depth comes from rules and tone, never from shadow.
- Identity row closed by a 2px ink rule, then the measured score, then the reference range.
- A three-segment reference-range band (LOW 0–19 / MEDIUM 20–49 / HIGH 50–100) with an ink marker. It is the signature, reused for level distribution.
- Mono tabular figures for values and identifiers. Sans for words.
- Small corners (2–4px), dense but even spacing, and colour that carries meaning.

## Colors

A cool clinical neutral base with one institutional teal and a red/amber/green flag set that is used only for results.

### Primary
- **Institutional Teal** (`teal`): the header band, the primary submit actions ("Audit sekarang", "Simpan keputusan"), selected tab underline, multiselect chips, links, and the "Menunggu" (pending) step. It is Streamlit's `primaryColor` and `blueColor`, so native info alerts tint teal.
- **Deep Teal** (`teal-deep`): hover state for primary buttons only.
- **Teal Wash** (`teal-wash`): text selection background.
- **Band Caption** (`band-caption`): the caption line inside the teal header band, and nowhere else.

### Tertiary (result flags)
- **Flag Red** (`flag-high`): HIGH level, "Bahaya" step status, error alerts (`redColor`).
- **Flag Amber** (`flag-med`): MEDIUM level, "Peringatan" status, warning alerts (`yellowColor` and `orangeColor`).
- **Flag Green** (`flag-low`): LOW level, "Lolos" status, success alerts (`greenColor`).
- **Range Washes** (`range-low`, `range-med`, `range-high`): the inactive segments of the reference-range band and of the Riwayat distribution. The active segment switches to the full flag colour.

### Neutral
- **Cool Grey Ground** (`ground`): app background and step-strip cell fill.
- **Ground Deep** (`ground-deep`): Streamlit secondary background (input fills) and the fill of not-yet-played trace steps.
- **Sheet White** (`sheet`): sheets, forms, sidebar, empty state, and text on teal or flag fills.
- **Sheet Tint** (`sheet-tint`): code-block and dataframe-header background.
- **Rule** (`rule`): 1px sheet borders, tab-list baseline, sidebar edge, widget borders.
- **Soft Rule** (`rule-soft`): the divider above the meta row and the border around code blocks.
- **Ink** (`ink`): body text, the 2px identity rule, and the range marker.
- **Ink 2** (`ink-2`): labels, captions, range-scale text, and the "/100" denominator.
- **Slate** (`slate-skip`): the "Dilewati" (skipped) step status only.

### Named Rules
**The Result-Owns-Colour Rule.** Red, amber, and green appear only when they report a level or status: score, flag, range segment, step status, alert. They are never decoration, accents, or illustration.

**The One Institution Rule.** Teal is the shell's voice: header band, primary action, selection. It never stands in for a result level.

## Typography

**Body Font:** Public Sans (self-hosted variable woff2, weights 100–900, from `static/fonts`)
**Label/Mono Font:** Roboto Mono (self-hosted variable woff2, weights 100–700)

**Character:** Public Sans is a neutral civic sans that reads like a government form. Roboto Mono gives every value a printed-instrument look. The contrast between the two encodes the difference between a word and a measurement.

### Hierarchy
- **Score** (Roboto Mono 600, 3.4rem, line-height 1, -0.03em, tabular): the single large measured value on a result sheet, coloured by its level ink. Drops to 2.6rem at ≤640px.
- **Headline** (Public Sans 650, 1.45rem, 1.2): the product name in the header band. The sidebar title uses the same weight at 1.25rem.
- **Title** (Public Sans 650): the selected tab (0.98rem) and in-sheet section heads ("Rekomendasi", "Temuan", "Jejak eksekusi") in bold body.
- **Body** (Public Sans 400, 1rem): Streamlit default copy, alerts, recommendation text.
- **Table** (Public Sans 400, 0.88rem): static tables (findings, trace). Cells wrap instead of truncating.
- **Data** (Roboto Mono 400, 0.98rem, tabular): identity-row values (audit #, server, tool), meta-row numbers, rule IDs, Bobot, durations.
- **Label** (Public Sans 600, 0.74rem, 0.06em, uppercase): field labels in the identity row ("AUDIT", "SERVER", "TOOL", "MESIN", Riwayat summary counts). It always labels the value directly beneath it.
- **Flag** (Public Sans 700, 0.86rem, 0.04em): the level text inside a flag chip.
- **Scale** (Public Sans 400, 0.76rem, tabular): range-scale captions and distribution labels. The active level's caption steps up to ink at weight 650.

### Named Rules
**The Measurement Rule.** If it's a number or an identifier (score, count, ID, rule code, weight, duration, server or tool name in the identity row), set it in Roboto Mono with tabular figures. If it's a word (engine name, "Dipakai"/"Tidak", status), keep it in Public Sans. The helpers enforce this with a `txt` class on word values.

**Adaptation: canvas grids stay sans.** The Riwayat history grid and the decision trail are `st.dataframe`, which renders on a canvas. Streamlit cannot set per-column fonts there, so they render entirely in Public Sans. Mono is applied in static tables (`st.table`: findings, trace) and in custom HTML components. Range-scale captions use Public Sans with tabular figures rather than mono, so the band reads as a printed axis.

## Layout

Wide layout, main container capped at 1480px with 2rem top padding. The page order is fixed: teal header band, then Streamlit's native tabs (Audit / Riwayat / Keputusan) directly beneath. The band is a contained, rounded block above the tabs, not a full-bleed bar. Tabs cannot live inside custom HTML, so the band and tabs are separate blocks with a 4px gap.

- **Audit:** form column 2/5 on the left, result sheet 3/5 on the right (`gap="large"`).
- **Keputusan:** result sheet 3/5 on the left, decision form 2/5 on the right.
- **Riwayat:** a summary identity row (Total, HIGH, MEDIUM, Menunggu), then the full-width level distribution band, then two filter columns, the history grid, and two download buttons.

Spacing follows a tight 2 / 6 / 10 / 14px rhythm inside components. Sheets are padded 18px × 20px. Identity-row cells are spaced 10px vertical × 36px horizontal and wrap. Meta-row items are spaced 6px × 28px. At ≤640px the band padding tightens to 14px × 16px, the score shrinks, and static tables keep a 560px minimum width inside a horizontal scroller rather than crushing their columns. Streamlit stacks the columns on narrow viewports.

## Elevation & Depth

The system is flat. No element uses `box-shadow`. Depth is tonal: white sheets sit on the grey ground, bounded by a 1px `rule` border. Hierarchy within a sheet comes from rules of different weights: the 2px ink rule under the identity row, then 1px soft rules between sub-blocks. The only motion is the range marker sliding to its score position (600ms, `cubic-bezier(0.16, 1, 0.3, 1)`), disabled under `prefers-reduced-motion`. The trace replay steps through the real steps at 0.45s each and can be toggled off in the sidebar.

### Named Rules
**The Paper-On-Desk Rule.** Surfaces are separated by rules and tone, never by shadow, blur, glass, or gradient.

**The Ruled Header Rule.** Every result sheet opens with an identity row closed by a 2px ink rule. Nothing else on the page uses a 2px ink rule.

## Shapes

Corners are small and squarish. Sheets, forms, the header band, alerts, and buttons use 4px (`rounded.sheet`). Flag chips use 3px. Range and distribution segments and step-strip cells use 2px, and the range marker uses 1px. Range segments are separated by 2px gaps rather than borders. Step-strip cells carry a 4px top bar in their status colour, like a coloured tab on a filing card. The empty state is the only element with a dashed border.

## Components

### Buttons
- **Shape:** gently squared (4px), via Streamlit `baseRadius`.
- **Primary:** teal fill, white text, full column width at the foot of a form ("Audit sekarang", "Simpan keputusan").
- **Hover:** fill and border shift to deep teal. No lift, no shadow.
- **Secondary:** Streamlit's default bordered buttons for downloads, on the sheet border colour.

### Header Band
A teal, 4px-rounded block with a 30px outline shield SVG (stroke `currentColor`), the product name in Headline, and the caption in `band-caption`. It sits contained in the main column above the native tabs.

### Sheets / Containers
- **Corner Style:** 4px.
- **Background:** sheet white on the ground.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px `rule`.
- **Internal Padding:** 18px × 20px for keyed sheet containers. Forms use Streamlit's default padding.

### Inputs / Fields
Streamlit native fields themed through config.toml: `ground-deep` fill, `rule` widget borders, 4px radius, and teal focus via `primaryColor`. Multiselect chips fill teal with white text.

### Identity Row (signature)
A definition list that wraps horizontally. Uppercase Label `dt` sits over a Data `dd`, and a 2px ink rule closes the row. Values are always HTML-escaped before insertion. Word values (engine name) switch to sans. The same row serves as the Riwayat summary.

### Score Block and Reference Range (signature)
The large mono score is coloured by level ink, followed by a mono "/100" in `ink-2`, then the flag chip. Beneath is a 12px track of three segments sized in proportion to their ranges (20 / 30 / 51). The active segment is the full flag colour and the others are washes. A 3px ink marker extends 6px above and below the track at `left: score%`. The scale captions sit under each segment, and the active caption is in ink at weight 650. The band has `role="img"` with a spoken summary. Only validated levels and clamped integers reach this HTML.

### Level Distribution (Riwayat)
The same segment vocabulary used as a count bar. Each level's segment grows in proportion to its count. An empty level shrinks to its label width and keeps its wash colour. Labels give the level in sans and the count in mono.

### Step Strip (execution trace)
A wrapping ordered list of cells (min 96px) on the ground fill, each with a 4px top bar and a status word in that status colour (Lolos / Peringatan / Bahaya / Dilewati / Menunggu), above a fixed step label. Labels come only from code, never from tool text. It is paired with a static trace table where Status is coloured and Waktu is mono.

### Static Tables (findings, trace)
`st.table` with no index, 0.88rem, top-aligned cells that wrap so evidence is never truncated. The Aturan and Bobot columns are mono. **Adaptation:** findings carry no per-rule level, so the findings table has no per-finding flag column. Only the overall score gets a flag, and Bobot (weight) is shown as the value.

### Alerts
Native `st.error` / `st.warning` / `st.success` / `st.info` with 4px corners. They are themed through config.toml's `redColor`, `yellowColor`/`orangeColor`, `greenColor`, and `blueColor` (teal), so alerts speak the same flag palette.

### Untrusted Text
Tool names and descriptions are untrusted. They are HTML-escaped (and neutralized) inside identity rows, and shown elsewhere through `st.code` (full description, word diff) or `st.table` / `st.dataframe`. They are never passed to `unsafe_allow_html`. Labels mark them "(data tidak dipercaya)".

### Navigation
Streamlit native tabs with Material Symbols icons. The tab list sits on a 1px `rule` baseline with an 8px gap. The selected tab is Public Sans 650 in ink with a teal underline. The sidebar is a white settings panel with a 1px right rule, holding the engine choice, the animation toggle, and privacy captions.

## Do's and Don'ts

### Do:
- **Do** open every result view with the identity row, the 2px ink rule, the mono score with its flag, and the reference-range band, in that order.
- **Do** reuse the range-segment vocabulary (12px segments, 2px gaps, wash vs. full flag colour) for any level-based summary.
- **Do** set numbers and identifiers in Roboto Mono with tabular figures, and words in Public Sans.
- **Do** separate surfaces with 1px `rule` borders on white sheets over the grey ground.
- **Do** escape untrusted tool text in HTML, or route it through `st.code` / `st.table`.
- **Do** theme native Streamlit elements through config.toml before reaching for CSS overrides.

### Don't:
- **Don't** use shadows, glass, blur, or gradients on any surface.
- **Don't** use red, amber, or green for anything that is not a level or status.
- **Don't** use teal to signal a result level.
- **Don't** render tool names or descriptions as HTML or markdown.
- **Don't** truncate evidence in tables. Wrap it, and scroll horizontally on narrow screens.
