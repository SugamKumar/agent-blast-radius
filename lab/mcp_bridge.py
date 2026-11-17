"""Run the lab's servers as real MCP servers over Streamable HTTP.

Each server becomes an MCP server acting as an OAuth resource server:

  * every request must carry `Authorization: Bearer <token>`;
  * a TokenVerifier checks the token's signature and expiry;
  * when audience validation is on, the SDK's own bearer middleware refuses
    any token not issued for this server's URL
    (`AuthSettings.validate_token_resource`, the RFC 8707 resource check).

The agent side talks to them with the MCP client. The issue tracker's call
to the notes server is also a real HTTP request, so token passthrough is a
real forwarded bearer token.

Requires the `mcp` Python SDK, version 2.x.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .servers.base import Tool, ToolServer
from .tokens import AuthError, verify

ISSUER_URL = "http://127.0.0.1:8800"  # the (mock) authorization server's identity
UPSTREAM_HEADER = "x-upstream-service"
NOT_AUTHORIZED = "NOT_AUTHORIZED: "
BAD_ARGUMENTS = "BAD_ARGUMENTS: "

_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="mcp-call")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --------------------------------------------------------------------------
# Server side
# --------------------------------------------------------------------------

class LabTokenVerifier:
    """Checks signature and expiry, and reports which resource the token is for."""

    def __init__(self, server_name: str, resource_url: str) -> None:
        self.server_name = server_name
        self.resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = verify(token)
        except AuthError:
            return None
        # Translate the lab's short audience name into this server's URL so the
        # SDK can compare it with resource_server_url.
        resource = self.resource_url if claims["aud"] == self.server_name else claims["aud"]
        return AccessToken(
            token=token,
            client_id=claims["act"],
            scopes=claims["scope"],
            expires_at=claims["exp"],
            resource=resource,
            subject=claims["sub"],
            claims=claims,
        )


def _dispatch(server: ToolServer, tool_name: str, args: dict, ctx: Context) -> str:
    """Hand an MCP tool call to the lab server's own authorization and logic."""
    access = get_access_token()
    if access is None:
        raise ToolError(NOT_AUTHORIZED + "no bearer token")
    headers = ctx.headers or {}
    # A header is client-supplied input, not proof of identity. The vulnerable
    # notes server trusts it anyway (trust_upstream=True); that is the bug.
    via = headers.get(UPSTREAM_HEADER)
    try:
        return server.call(tool_name, args, access.token, via=via)
    except AuthError as exc:
        raise ToolError(NOT_AUTHORIZED + str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolError(BAD_ARGUMENTS + str(exc)) from exc


def make_mcp_server(server: ToolServer, port: int) -> MCPServer:
    resource_url = f"http://127.0.0.1:{port}/mcp"
    app = MCPServer(
        name=server.name,
        token_verifier=LabTokenVerifier(server.name, resource_url),
        auth=AuthSettings(
            issuer_url=ISSUER_URL,
            resource_server_url=resource_url,
            # The secure setting. Off when the lab scenario disables audience
            # validation, or when the server blindly trusts upstream callers.
            validate_token_resource=server.validate_audience and not server.trust_upstream,
        ),
        log_level="ERROR",
    )
    descriptions = {name: tool.description for name, tool in server.tools.items()}

    if server.name == "issues":

        @app.tool(description=descriptions["list_issues"])
        def list_issues(ctx: Context) -> str:
            return _dispatch(server, "list_issues", {}, ctx)

        @app.tool(description=descriptions["get_issue"])
        def get_issue(issue_id: int, ctx: Context) -> str:
            return _dispatch(server, "get_issue", {"issue_id": issue_id}, ctx)

        @app.tool(description=descriptions["add_comment"])
        def add_comment(issue_id: int, body: str, ctx: Context) -> str:
            return _dispatch(server, "add_comment", {"issue_id": issue_id, "body": body}, ctx)

        @app.tool(description=descriptions["attach_note"])
        def attach_note(issue_id: int, note_id: str, ctx: Context) -> str:
            return _dispatch(server, "attach_note", {"issue_id": issue_id, "note_id": note_id}, ctx)

        @app.tool(description=descriptions["close_issue"])
        def close_issue(issue_id: int, ctx: Context) -> str:
            return _dispatch(server, "close_issue", {"issue_id": issue_id}, ctx)

        @app.tool(description=descriptions["delete_issue"])
        def delete_issue(issue_id: int, ctx: Context) -> str:
            return _dispatch(server, "delete_issue", {"issue_id": issue_id}, ctx)

    elif server.name == "notes":

        @app.tool(description=descriptions["list_notes"])
        def list_notes(ctx: Context) -> str:
            return _dispatch(server, "list_notes", {}, ctx)

        @app.tool(description=descriptions["read_note"])
        def read_note(note_id: str, ctx: Context) -> str:
            return _dispatch(server, "read_note", {"note_id": note_id}, ctx)

    else:
        raise ValueError(f"no MCP wrapper for server '{server.name}'")
    return app


@dataclass
class RunningServer:
    name: str
    url: str
    _uvicorn: uvicorn.Server
    _thread: threading.Thread

    def stop(self) -> None:
        self._uvicorn.should_exit = True
        self._thread.join(timeout=5)


def serve(server: ToolServer, port: int | None = None) -> RunningServer:
    """Start one MCP server on localhost in a background thread."""
    port = port or _free_port()
    app = make_mcp_server(server, port).streamable_http_app(
        json_response=True, stateless_http=True
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True, name=f"mcp-{server.name}")
    thread.start()
    deadline = time.time() + 10
    while not uv.started:
        if time.time() > deadline:
            raise RuntimeError(f"MCP server '{server.name}' did not start")
        time.sleep(0.01)
    return RunningServer(server.name, f"http://127.0.0.1:{port}/mcp", uv, thread)


# --------------------------------------------------------------------------
# Client side
# --------------------------------------------------------------------------

def _result_text(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


class RemoteToolServer:
    """Drop-in stand-in for a ToolServer that reaches it over MCP.

    `policy_tools` carries what the agent side knows about each tool for
    policy purposes (required scope, data class). MCP itself does not carry
    that, so it comes from local configuration, as it would in a real gateway.
    """

    def __init__(self, name: str, url: str, policy_tools: dict[str, Tool]) -> None:
        self.name = name
        self.url = url
        self.tools = dict(policy_tools)

    async def _call_async(self, tool_name: str, args: dict, token: str, via: str | None):
        headers = {"Authorization": f"Bearer {token}"}
        if via:
            headers[UPSTREAM_HEADER] = via
        async with create_mcp_http_client(headers=headers) as http:
            async with Client(streamable_http_client(self.url, http_client=http)) as client:
                return await client.call_tool(tool_name, args)

    def call(self, tool_name: str, args: dict, token: str, via: str | None = None) -> str:
        # Run in a helper thread so this also works when called from inside a
        # server's own event loop (the issue tracker calling the notes server).
        future = _pool.submit(asyncio.run, self._call_async(tool_name, args, token, via))
        try:
            result = future.result(timeout=30)
        except Exception as exc:  # transport-level refusal, e.g. HTTP 401/403
            raise AuthError(f"request refused by '{self.name}' server: {_describe(exc)}") from exc

        text = _result_text(result)
        if result.is_error:
            if NOT_AUTHORIZED in text:
                raise AuthError(text.split(NOT_AUTHORIZED, 1)[1])
            raise ValueError(text.split(BAD_ARGUMENTS, 1)[-1])
        return text

    async def _list_async(self, token: str) -> list[str]:
        headers = {"Authorization": f"Bearer {token}"}
        async with create_mcp_http_client(headers=headers) as http:
            async with Client(streamable_http_client(self.url, http_client=http)) as client:
                return [tool.name for tool in (await client.list_tools()).tools]

    def list_remote_tools(self, token: str) -> list[str]:
        return _pool.submit(asyncio.run, self._list_async(token)).result(timeout=30)


def _describe(exc: BaseException) -> str:
    """Flatten exception groups into one short line."""
    inner = getattr(exc, "exceptions", None)
    if inner:
        return "; ".join(_describe(e) for e in inner)
    return f"{type(exc).__name__}: {exc}"[:200]


# --------------------------------------------------------------------------
# Wiring a whole scenario over MCP
# --------------------------------------------------------------------------

def build_over_mcp(scenario, session: str, **build_kwargs):
    """Like scenarios.build, but every hop is a real MCP call over HTTP.

    Returns (world, audit, client, stop). Call stop() when the trial is done.
    """
    from .scenarios import build  # local import: scenarios must not need mcp

    world, audit, client = build(scenario, session, **build_kwargs)
    # build() connects only some servers to the agent, but both must run,
    # because the issue tracker calls the notes server itself.
    issues = next(iter(client.connections.values())).server if "issues" in client.connections else None
    if issues is None:
        raise ValueError("scenario must connect the issues server")
    notes = issues.notes_server

    running_notes = serve(notes)
    remote_notes = RemoteToolServer("notes", running_notes.url, notes.tools)
    issues.notes_server = remote_notes  # server-to-server hop now goes over HTTP
    running_issues = serve(issues)
    remotes = {
        "issues": RemoteToolServer("issues", running_issues.url, issues.tools),
        "notes": remote_notes,
    }
    for name, conn in client.connections.items():
        conn.server = remotes[name]

    def stop() -> None:
        running_issues.stop()
        running_notes.stop()

    return world, audit, client, stop
