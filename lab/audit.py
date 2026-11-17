"""Append-only audit log of every tool call attempt, allowed or denied.

One JSON object per line. The detection rules in lab/detections read this.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditLog:
    session: str
    config: str
    events: list[dict] = field(default_factory=list)

    def record(
        self,
        *,
        server: str,
        tool: str,
        args: dict,
        claims: dict | None,
        decision: str,           # "allowed" | "denied"
        decided_by: str,         # "gateway" | "server" | "-"
        reason: str = "",
        data_class: str = "",    # "private_read" | "public_write" | "public_read"
        via: str | None = None,  # set when one server calls another
        in_task_scope: bool = True,
        in_task_args: bool = True,  # False: tool is allowed, but not on this resource
    ) -> None:
        self.events.append(
            {
                "ts": round(time.time(), 3),
                "seq": len(self.events),
                "session": self.session,
                "config": self.config,
                "server": server,
                "tool": tool,
                "args": args,
                "token": None
                if claims is None
                else {
                    "sub": claims["sub"],
                    "act": claims["act"],
                    "aud": claims["aud"],
                    "scope": claims["scope"],
                    "kind": claims["kind"],
                    "expires": claims["exp"] is not None,
                },
                "decision": decision,
                "decided_by": decided_by,
                "reason": reason,
                "data_class": data_class,
                "via": via,
                "in_task_scope": in_task_scope,
                "in_task_args": in_task_args,
            }
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(event) + "\n")


def read_events(path: Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
