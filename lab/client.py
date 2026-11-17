"""Agent-side tool client: what an MCP client does for an agent.

It holds one connection (server + token) per tool server, shows the model a
flat list of tools named `server__tool`, routes calls, and writes the audit
log for every attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditLog
from .gateway import Gateway
from .servers.base import ToolServer
from .tokens import AuthError, verify


# Arguments that name a resource (which note, which issue).
RESOURCE_ARGS = {"note_id", "issue_id"}


@dataclass
class Connection:
    server: ToolServer
    token: str


@dataclass
class ToolClient:
    audit: AuditLog
    task_allowlist: set[str]
    # Resources the task may touch, by argument name, e.g.
    # {"note_id": {"meeting-notes"}}. None means no limit is declared.
    task_resources: dict[str, set[str]] | None = None
    # Fail closed: a tool that reads private data, writes, or destroys may
    # only be used on a resource the task explicitly declares. With False, an
    # argument the task says nothing about is allowed (the first version).
    fail_closed_resources: bool = True
    connections: dict[str, Connection] = field(default_factory=dict)
    gateway: Gateway | None = None

    def connect(self, server: ToolServer, token: str) -> None:
        self.connections[server.name] = Connection(server, token)

    def tool_definitions(self) -> list[dict]:
        """Tool list in the shape the Anthropic Messages API expects."""
        definitions = []
        for server_name, conn in self.connections.items():
            for tool in conn.server.tools.values():
                qualified = f"{server_name}__{tool.name}"
                if self.gateway is not None and not self.gateway.visible(qualified):
                    continue
                definitions.append(
                    {
                        "name": qualified,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                    }
                )
        return definitions

    def _args_in_task(self, tool, args: dict) -> bool:
        """Is this call aimed only at resources the task declares?"""
        if tool is not None and tool.data_class == "public_read":
            return True  # reading public data needs no resource grant
        declared = self.task_resources or {}
        for name in RESOURCE_ARGS & set(args):
            allowed = declared.get(name)
            if allowed is None:
                if self.fail_closed_resources:
                    return False
                continue
            if str(args[name]) not in allowed:
                return False
        return True

    def call(self, qualified: str, args: dict) -> str:
        """Run one tool call. Always returns text for the model; never raises."""
        server_name, _, tool_name = qualified.partition("__")
        in_scope = qualified in self.task_allowlist
        in_args = self._args_in_task(None, args)  # refined below once the tool is known
        conn = self.connections.get(server_name)

        if conn is None or tool_name not in conn.server.tools:
            self.audit.record(
                server=server_name, tool=tool_name, args=args, claims=None,
                decision="denied", decided_by="client",
                reason="agent is not connected to this tool", in_task_scope=in_scope,
                in_task_args=in_args,
            )
            return f"ERROR: unknown tool '{qualified}'"

        tool = conn.server.tools[tool_name]
        in_args = self._args_in_task(tool, args)
        try:
            claims = verify(conn.token)
        except AuthError:
            claims = None

        def log(decision: str, decided_by: str, reason: str = "") -> None:
            self.audit.record(
                server=server_name, tool=tool_name, args=args, claims=claims,
                decision=decision, decided_by=decided_by, reason=reason,
                data_class=tool.data_class, in_task_scope=in_scope, in_task_args=in_args,
            )

        if self.gateway is not None:
            allowed, reason = self.gateway.check(qualified, tool, args, in_task_args=in_args)
            if not allowed:
                log("denied", "gateway", reason)
                return f"ERROR: blocked by policy: {reason}"

        try:
            result = conn.server.call(tool_name, args, conn.token)
        except AuthError as exc:
            log("denied", "server", str(exc))
            return f"ERROR: not authorized: {exc}"
        except (KeyError, TypeError, ValueError) as exc:
            log("error", "server", f"bad arguments: {exc}")
            return f"ERROR: bad arguments: {exc}"

        log("allowed", "server")
        if self.gateway is not None:
            self.gateway.observe(tool)
        return result
