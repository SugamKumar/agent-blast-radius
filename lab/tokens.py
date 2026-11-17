"""Minimal signed access tokens and a toy authorization server.

This is a teaching model of OAuth-style access tokens, not a real OAuth
implementation. It keeps only the properties the lab needs to reason about:

  sub    who the token acts for (the human user)
  act    which agent is acting on the user's behalf
  aud    the ONE server the token is meant for ("*" = any server, like a
         personal access token)
  scope  what the token may do
  exp    when it stops working (None = never, like a personal access token)
  kind   "oauth" (short-lived, audience-bound) or "pat" (personal token)

Tokens are HMAC-signed so servers can verify them without shared state.
The signing key is hard-coded because everything here is a local mock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

_SIGNING_KEY = b"agent-authz-lab-local-only-key"


class AuthError(Exception):
    """Raised when a token is invalid or does not permit the request."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload: bytes) -> str:
    return _b64(hmac.new(_SIGNING_KEY, payload, hashlib.sha256).digest())


def mint(
    *,
    sub: str,
    act: str,
    aud: str,
    scope: list[str],
    ttl_seconds: int | None = 300,
    kind: str = "oauth",
) -> str:
    """Create a signed token. ttl_seconds=None means it never expires."""
    claims = {
        "sub": sub,
        "act": act,
        "aud": aud,
        "scope": sorted(scope),
        "exp": None if ttl_seconds is None else int(time.time()) + ttl_seconds,
        "kind": kind,
    }
    payload = json.dumps(claims, sort_keys=True).encode()
    return f"{_b64(payload)}.{_sign(payload)}"


def verify(token: str) -> dict:
    """Check signature and expiry; return the claims. Raises AuthError."""
    try:
        body, signature = token.split(".")
        payload = _unb64(body)
    except Exception as exc:  # malformed token
        raise AuthError("malformed token") from exc
    if not hmac.compare_digest(signature, _sign(payload)):
        raise AuthError("bad signature")
    claims = json.loads(payload)
    if claims["exp"] is not None and claims["exp"] < time.time():
        raise AuthError("token expired")
    return claims


def has_scope(claims: dict, required: str) -> bool:
    return "*" in claims["scope"] or required in claims["scope"]


@dataclass
class AuthServer:
    """Toy authorization server.

    `grants` records what the user has approved for one agent, per server:
        {"issues": ["issues:read"], "notes": ["notes:read"]}
    Tokens can only be minted or exchanged within those grants.
    """

    user: str
    agent: str
    grants: dict[str, list[str]] = field(default_factory=dict)

    def token_for(self, audience: str, ttl_seconds: int = 300) -> str:
        """Mint an audience-bound token carrying exactly the granted scopes."""
        if audience not in self.grants:
            raise AuthError(f"no grant for audience '{audience}'")
        return mint(
            sub=self.user,
            act=self.agent,
            aud=audience,
            scope=self.grants[audience],
            ttl_seconds=ttl_seconds,
        )

    def exchange(self, subject_token: str, audience: str, scope: list[str]) -> str:
        """Token exchange (the RFC 8693 idea): trade a token for a narrower one
        aimed at a different server. Refused unless the user granted every
        requested scope for that audience.
        """
        claims = verify(subject_token)
        granted = self.grants.get(audience, [])
        missing = [s for s in scope if s not in granted]
        if missing:
            raise AuthError(
                f"exchange denied: {claims['act']} has no grant for {missing} on '{audience}'"
            )
        return mint(
            sub=claims["sub"],
            act=claims["act"],
            aud=audience,
            scope=scope,
            ttl_seconds=60,
        )
