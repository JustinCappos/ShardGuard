"""MCP authentication credential resolution.

Reads an optional `auth` block from an MCP registry entry and returns the
headers to attach to HTTP requests for that server.

Currently supported auth types:

    {"type": "none"}                                          # default when absent
    {"type": "bearer", "token_env": "GITHUB_PAT"}             # Authorization: Bearer <value>
    {"type": "bearer", "token_env": "KEY", "header": "X-Api-Key", "scheme": ""}
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_HEADER = "Authorization"
DEFAULT_SCHEME = "Bearer"


class AuthConfigError(ValueError):
    """Raised when an MCP entry's `auth` block is malformed or missing a referenced env var."""


def resolve_http_headers(name: str, cfg: dict[str, Any]) -> dict[str, str]:
    auth = cfg.get("auth")
    if not auth:
        return {}
    if not isinstance(auth, dict):
        raise AuthConfigError(f"{name!r}: auth must be an object")

    atype = (auth.get("type") or "").strip().lower()
    if atype in {"", "none"}:
        return {}
    if atype == "bearer":
        return _resolve_bearer(name, auth)

    raise AuthConfigError(f"{name!r}: unsupported auth.type {atype!r}")


def _resolve_bearer(name: str, auth: dict[str, Any]) -> dict[str, str]:
    token_env = auth.get("token_env")
    if not token_env or not isinstance(token_env, str):
        raise AuthConfigError(f"{name!r}: auth.token_env is required for bearer")

    token = os.environ.get(token_env)
    if not token:
        raise AuthConfigError(
            f"{name!r}: env var {token_env!r} is unset; cannot build bearer credential"
        )

    header = (auth.get("header") or DEFAULT_HEADER).strip() or DEFAULT_HEADER
    scheme = auth.get("scheme")
    if scheme is None:
        scheme = DEFAULT_SCHEME
    scheme = scheme.strip()

    value = f"{scheme} {token}".strip() if scheme else token
    return {header: value}
