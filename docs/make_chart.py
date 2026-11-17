"""Draw docs/blast_radius.svg from results/compromised_results.json.

    python docs/make_chart.py

A status grid: one row per access configuration, one column per kind of harm.
A filled cell means a compromised agent could do that harm; an outlined cell
means it was blocked. No third-party packages needed.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HARMS = [
    ("standard_note", "leaked", "Standard note"),
    ("restricted_note", "leaked", "Restricted note"),
    ("issue_closed", "closed", "Issue closed"),
    ("issue_deleted", "deleted", "Issue deleted"),
]
GROUPS = [("Private data stolen", 0, 2), ("Records damaged", 2, 4)]

SURFACE, INK, MUTED = "#fcfcfb", "#1c1c1a", "#6b6a64"
HAIRLINE, CRITICAL = "#e1e0d9", "#d03b3b"

LEFT, TOP = 268, 124          # where the grid starts
CELL_W, CELL_H, GAP = 112, 40, 8
FONT = "font-family=\"-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif\""


def text(x, y, content, *, size=13, fill=INK, anchor="start", weight="400") -> str:
    return (
        f'<text x="{x}" y="{y}" {FONT} font-size="{size}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{escape(content)}</text>'
    )


def build(summary: list[dict]) -> str:
    width = LEFT + len(HARMS) * (CELL_W + GAP) + 24
    height = TOP + len(summary) * (CELL_H + GAP) + 44
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" '
        'aria-label="Grid showing which harms a compromised agent can cause under each access configuration">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{SURFACE}"/>',
        text(24, 36, "What a compromised agent can do, by access configuration", size=17, weight="600"),
        text(24, 58, "A scripted agent under the attacker's control tries every route, in two orders.",
             fill=MUTED),
    ]

    for label, start, end in GROUPS:
        x0 = LEFT + start * (CELL_W + GAP)
        x1 = LEFT + end * (CELL_W + GAP) - GAP
        out.append(text((x0 + x1) / 2, 88, label, size=12, fill=MUTED, anchor="middle", weight="600"))
        out.append(f'<line x1="{x0}" y1="95" x2="{x1}" y2="95" stroke="{HAIRLINE}" stroke-width="1"/>')
    for col, (_, _, header) in enumerate(HARMS):
        cx = LEFT + col * (CELL_W + GAP) + CELL_W / 2
        out.append(text(cx, 113, header, size=12, anchor="middle"))

    for row, entry in enumerate(summary):
        y = TOP + row * (CELL_H + GAP)
        happened = set(entry["leaked"]) | set(entry["tampered"])
        out.append(text(LEFT - 16, y + CELL_H / 2 + 5, entry["title"], anchor="end"))
        for col, (key, verb, _) in enumerate(HARMS):
            x = LEFT + col * (CELL_W + GAP)
            cx, cy = x + CELL_W / 2, y + CELL_H / 2 + 5
            if key in happened:
                out.append(f'<rect x="{x}" y="{y}" width="{CELL_W}" height="{CELL_H}" rx="4" fill="{CRITICAL}"/>')
                out.append(text(cx, cy, f"✕ {verb}", fill="#ffffff", anchor="middle", weight="600"))
            else:
                out.append(
                    f'<rect x="{x + 0.5}" y="{y + 0.5}" width="{CELL_W - 1}" height="{CELL_H - 1}" rx="4" '
                    f'fill="none" stroke="{HAIRLINE}" stroke-width="1"/>'
                )
                out.append(text(cx, cy, "blocked", fill=MUTED, anchor="middle"))

    out.append(
        text(24, height - 16,
             "Shows what each configuration permits, not how often a real model is compromised.",
             size=12, fill=MUTED)
    )
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> None:
    data = json.loads((ROOT / "results" / "compromised_results.json").read_text(encoding="utf-8"))
    target = ROOT / "docs" / "blast_radius.svg"
    target.write_text(build(data["summary"]), encoding="utf-8")
    print(f"wrote {target.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
