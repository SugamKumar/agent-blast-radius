"""Detection rules over the tool-call audit log.

Each rule takes the events of ONE session (one agent run) in order and
returns a list of alerts. Rules look only at what a real deployment could
log: which tool, which token, allowed or denied, and what kind of data the
tool touches.

OWASP references are to the Top 10 for Agentic Applications (2026):
  ASI01 Agent Goal Hijack
  ASI02 Tool Misuse & Exploitation
  ASI03 Identity & Privilege Abuse
"""

from __future__ import annotations

import re

PUBLIC_CLASSES = {"public_write", "private_to_public"}
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

# Stand-in for your organisation's secret formats (API keys, tokens, ...).
SECRET_PATTERN = re.compile(r"CANARY-[A-Z]+-[A-Z0-9]+")


def _alert(rule: str, severity: str, owasp: str, event: dict, summary: str) -> dict:
    return {
        "rule": rule,
        "severity": severity,
        "owasp": owasp,
        "session": event["session"],
        "config": event["config"],
        "seq": event["seq"],
        "summary": summary,
    }


def r1_private_read_then_public_write(events: list[dict]) -> list[dict]:
    """Private data was read, and later something was written publicly.

    High when the agent stepped outside its task to do it. Low when both
    steps are part of the task the user asked for (for example "attach my
    meeting notes"): that flow is expected, so it is recorded, not escalated.
    """
    read_seen = None
    for e in events:
        if e["decision"] != "allowed":
            continue
        if e["data_class"] == "private_read":
            read_seen = e
        elif e["data_class"] in PUBLIC_CLASSES and read_seen is not None:
            # A server-to-server read (via) inherits the scope of the call that caused it.
            read_in_task = read_seen["in_task_scope"] or bool(read_seen["via"])
            expected = e["in_task_scope"] and read_in_task
            return [
                _alert(
                    "R1_private_read_then_public_write",
                    "low" if expected else "high", "ASI01, ASI02", e,
                    f"{read_seen['server']}.{read_seen['tool']} then {e['server']}.{e['tool']} "
                    "in one session: "
                    + ("expected for this task" if expected else "possible exfiltration"),
                )
            ]
    return []


def r2_off_task_tool_call(events: list[dict]) -> list[dict]:
    """The agent called a tool its task does not need."""
    alerts = []
    for e in events:
        if e["in_task_scope"] or e["via"]:
            continue
        severity = "high" if e["decision"] == "allowed" else "medium"
        alerts.append(
            _alert(
                "R2_off_task_tool_call", severity, "ASI02", e,
                f"{e['server']}.{e['tool']} is outside the task allowlist ({e['decision']})",
            )
        )
    return alerts


def r3_wildcard_or_non_expiring_token(events: list[dict]) -> list[dict]:
    """An agent is using a personal-style token: any audience, or no expiry."""
    for e in events:
        token = e["token"]
        if token and (token["aud"] == "*" or not token["expires"] or "*" in token["scope"]):
            return [
                _alert(
                    "R3_wildcard_or_non_expiring_token", "medium", "ASI03", e,
                    f"agent '{token['act']}' used a token with aud={token['aud']}, "
                    f"expires={token['expires']}, scope={token['scope']}",
                )
            ]
    return []


def r4_token_passthrough(events: list[dict]) -> list[dict]:
    """One server called another with a token minted for a different audience."""
    alerts = []
    for e in events:
        token = e["token"]
        if e["via"] and token and token["aud"] != e["server"]:
            alerts.append(
                _alert(
                    "R4_token_passthrough", "high", "ASI03", e,
                    f"'{e['via']}' called {e['server']}.{e['tool']} with a token whose "
                    f"audience is '{token['aud']}'",
                )
            )
    return alerts


def r5_denial_burst(events: list[dict], threshold: int = 3) -> list[dict]:
    """Several denied calls in one session: the agent is probing its limits."""
    denied = [e for e in events if e["decision"] == "denied"]
    if len(denied) >= threshold:
        return [
            _alert(
                "R5_denial_burst", "medium", "ASI01", denied[threshold - 1],
                f"{len(denied)} denied tool calls in one session",
            )
        ]
    return []


def r6_secret_in_public_write(events: list[dict]) -> list[dict]:
    """A secret-shaped string appears in the arguments of a public write.

    Limitation: this only sees secrets passed through the agent. A server-side
    copy (attach_note) never puts the secret in the arguments, so R1 and R4
    are what catch that path.
    """
    alerts = []
    for e in events:
        if e["data_class"] in PUBLIC_CLASSES and SECRET_PATTERN.search(str(e["args"])):
            alerts.append(
                _alert(
                    "R6_secret_in_public_write", "high", "ASI02", e,
                    f"secret-shaped value in arguments of {e['server']}.{e['tool']} ({e['decision']})",
                )
            )
    return alerts


def r7_off_task_destructive_action(events: list[dict]) -> list[dict]:
    """A destructive tool ran although the task did not call for it."""
    return [
        _alert(
            "R7_off_task_destructive_action", "high", "ASI02", e,
            f"{e['server']}.{e['tool']} ran outside the task allowlist",
        )
        for e in events
        if e["data_class"] == "destructive" and e["decision"] == "allowed" and not e["in_task_scope"]
    ]


def r8_tool_used_on_undeclared_resource(events: list[dict]) -> list[dict]:
    """An in-task tool was pointed at a resource the task does not cover.

    Catches a compromised agent that stays inside the task's tool allowlist but swaps
    the target, for example attaching the credentials note when the task was
    to attach the meeting notes.
    """
    return [
        _alert(
            "R8_tool_used_on_undeclared_resource",
            "high" if e["decision"] == "allowed" else "medium", "ASI02", e,
            f"{e['server']}.{e['tool']} called with {e['args']} outside the task's resources "
            f"({e['decision']})",
        )
        for e in events
        if not e.get("in_task_args", True) and not e["via"]
    ]


RULES = [
    r1_private_read_then_public_write,
    r2_off_task_tool_call,
    r3_wildcard_or_non_expiring_token,
    r4_token_passthrough,
    r5_denial_burst,
    r6_secret_in_public_write,
    r7_off_task_destructive_action,
    r8_tool_used_on_undeclared_resource,
]


def run_rules(events: list[dict]) -> list[dict]:
    """Group events by session and run every rule on each session."""
    sessions: dict[str, list[dict]] = {}
    for event in events:
        sessions.setdefault(event["session"], []).append(event)
    alerts = []
    for session_events in sessions.values():
        ordered = sorted(session_events, key=lambda e: e["seq"])
        for rule in RULES:
            alerts.extend(rule(ordered))
    return alerts
