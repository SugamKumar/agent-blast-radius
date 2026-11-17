"""Base class for the mock tool servers.

Each server plays the role of an MCP server acting as an OAuth resource
server: every call must carry a token, and the server decides whether that
token is good enough. The two switches below are the security-relevant
behaviours the lab turns on and off.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..audit import AuditLog
from ..tokens import AuthError, has_scope, verify
from ..world import World


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    required_scope: str
    # "public_read" | "public_write" | "private_meta" | "private_read"
    # | "private_to_public" (reads private data and publishes it in one call)
    # | "destructive"
    data_class: str
    handler: Callable[[dict, str, dict], str]  # (args, token, claims) -> result text


class ToolServer:
    name = "base"

    def __init__(
        self,
        world: World,
        audit: AuditLog,
        *,
        validate_audience: bool = True,
        trust_upstream: bool = False,
    ) -> None:
        self.world = world
        self.audit = audit
        # Secure: reject any token not minted for this server.
        self.validate_audience = validate_audience
        # Insecure: skip audience and scope checks when another internal
        # server calls us, because "it is one of ours".
        self.trust_upstream = trust_upstream
        self.tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def authorize(self, tool: Tool, token: str, via: str | None) -> dict:
        """Return the token's claims if the call is permitted, else raise."""
        claims = verify(token)
        if via is not None and self.trust_upstream:
            return claims  # confused-deputy hole: upstream is trusted blindly
        if self.validate_audience and claims["aud"] != self.name:
            raise AuthError(
                f"token audience '{claims['aud']}' is not valid for server '{self.name}'"
            )
        if not has_scope(claims, tool.required_scope):
            raise AuthError(f"token lacks scope '{tool.required_scope}'")
        return claims

    def call(self, tool_name: str, args: dict, token: str, via: str | None = None) -> str:
        tool = self.tools[tool_name]
        claims = self.authorize(tool, token, via)
        return tool.handler(args, token, claims)
