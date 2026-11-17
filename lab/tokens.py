"""Access tokens and a small authorization server.

Tokens are real JSON Web Tokens (JWTs) in the shape of the OAuth 2.0 JWT
access token profile (RFC 9068):

  header   alg ES256, typ at+jwt, kid (which signing key)
  iss      who issued the token (the authorization server)
  sub      who the token acts for (the human user)
  act      who is acting on the user's behalf (the agent), as in RFC 8693
  aud      the ONE server the token is meant for
  scope    what the token may do, space-separated
  exp/iat  expiry and issue time
  jti      a unique id for this token

The authorization server signs with a private key. Tool servers verify with
the matching public key, published as a JWKS. So a tool server can check
tokens but cannot create them, which a shared signing secret would allow.

What is still simplified: there is no login, consent screen, discovery
endpoint or client registration. `AuthServer.grants` stands in for what the
user approved. The "personal access token" is modelled as a token with a
wildcard audience, every scope and no expiry, which no real issuer should
produce; that is the point of that scenario.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "https://auth.lab.example"
ALGORITHM = "ES256"
_KEY_ID = "lab-key-1"

# The authorization server's key pair. Only mint() touches the private half.
_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_PUBLIC_KEYS = {_KEY_ID: _PRIVATE_KEY.public_key()}


class AuthError(Exception):
    """Raised when a token is invalid or does not permit the request."""


def jwks() -> dict:
    """The public keys tool servers use to verify tokens (a JSON Web Key Set)."""
    keys = []
    for key_id, public_key in _PUBLIC_KEYS.items():
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(public_key, as_dict=True)
        keys.append({**jwk, "kid": key_id, "use": "sig", "alg": ALGORITHM})
    return {"keys": keys}


def mint(
    *,
    sub: str,
    act: str,
    aud: str,
    scope: list[str],
    ttl_seconds: int | None = 300,
    kind: str = "oauth",
) -> str:
    """Sign a token, as the authorization server. ttl_seconds=None means no expiry."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "act": {"sub": act},
        "client_id": act,
        "aud": aud,
        "scope": " ".join(sorted(scope)),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "token_kind": kind,
    }
    if ttl_seconds is not None:
        claims["exp"] = now + ttl_seconds
    return jwt.encode(
        claims, _PRIVATE_KEY, algorithm=ALGORITHM, headers={"typ": "at+jwt", "kid": _KEY_ID}
    )


def verify(token: str) -> dict:
    """Check signature, issuer and expiry; return the claims. Raises AuthError.

    The audience is deliberately NOT checked here. Each tool server decides
    whether to check it, because skipping that check is one of the mistakes
    the lab studies.
    """
    try:
        header = jwt.get_unverified_header(token)
        public_key = _PUBLIC_KEYS.get(header.get("kid"))
        if public_key is None:
            raise AuthError("unknown signing key")
        raw = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],  # never trust the token's own "alg"
            issuer=ISSUER,
            options={"verify_aud": False, "require": ["iss", "sub", "aud", "iat", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"invalid token: {exc}") from exc

    return {
        "iss": raw["iss"],
        "sub": raw["sub"],
        "act": raw["act"]["sub"],
        "aud": raw["aud"],
        "scope": raw["scope"].split(),
        "exp": raw.get("exp"),
        "jti": raw["jti"],
        "kind": raw.get("token_kind", "oauth"),
    }


def has_scope(claims: dict, required: str) -> bool:
    return "*" in claims["scope"] or required in claims["scope"]


@dataclass
class AuthServer:
    """Authorization server for one user and one agent.

    `grants` records what the user has approved for the agent, per server:
        {"issues": ["issues:read"], "notes": ["notes:read"]}
    Tokens can only be issued or exchanged within those grants.
    """

    user: str
    agent: str
    grants: dict[str, list[str]] = field(default_factory=dict)

    def token_for(self, audience: str, ttl_seconds: int = 300) -> str:
        """Issue an audience-bound token carrying exactly the granted scopes."""
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
        """Token exchange (RFC 8693): trade a token for a narrower one aimed at
        a different server. Refused unless the user granted every requested
        scope for that audience.
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
