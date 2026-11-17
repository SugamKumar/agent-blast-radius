"""Run the detection rules over an audit log.

    python -m lab.detect results/compromised_audit.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import read_events
from .detections.rules import RULES, run_rules


def matrix(alerts: list[dict], configs: list[str]) -> str:
    """Markdown table: which rule fired in which configuration."""
    rule_names = [r.__name__.split("_", 1)[0].upper() for r in RULES]
    fired = {(a["config"], a["rule"].split("_", 1)[0]) for a in alerts}
    lines = ["| Configuration | " + " | ".join(rule_names) + " |", "|---|" + "---|" * len(rule_names)]
    for config in configs:
        cells = ["fired" if (config, rule) in fired else "-" for rule in rule_names]
        lines.append(f"| {config} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_log")
    args = parser.parse_args(argv)

    events = read_events(Path(args.audit_log))
    alerts = run_rules(events)
    configs = list(dict.fromkeys(e["config"] for e in events))

    for a in alerts:
        print(f"[{a['severity']:<6}] {a['rule']:<36} {a['session']:<32} {a['summary']}")
    print()
    table = matrix(alerts, configs)
    print(table)

    out = Path(args.audit_log).with_name(Path(args.audit_log).stem.replace("_audit", "") + "_alerts.json")
    out.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    out.with_suffix(".md").write_text(table, encoding="utf-8")
    print(f"{len(alerts)} alerts written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
