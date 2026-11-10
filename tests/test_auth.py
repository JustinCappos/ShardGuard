import pytest

from shardguard.core.auth import AuthConfigError, resolve_http_headers


def test_no_auth_block_returns_empty():
    assert resolve_http_headers("mcp", {}) == {}


def test_type_none_returns_empty():
    assert resolve_http_headers("mcp", {"auth": {"type": "none"}}) == {}


def test_bearer_default_header_and_scheme(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "abc123")
    headers = resolve_http_headers(
        "mcp",
        {"auth": {"type": "bearer", "token_env": "TEST_TOKEN"}},
    )
    assert headers == {"Authorization": "Bearer abc123"}


def test_bearer_custom_header(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "abc123")
    headers = resolve_http_headers(
        "mcp",
        {
            "auth": {
                "type": "bearer",
                "token_env": "TEST_TOKEN",
                "header": "X-Api-Key",
                "scheme": "",
            }
        },
    )
    assert headers == {"X-Api-Key": "abc123"}


def test_bearer_custom_scheme(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "abc123")
    headers = resolve_http_headers(
        "mcp",
        {"auth": {"type": "bearer", "token_env": "TEST_TOKEN", "scheme": "Token"}},
    )
    assert headers == {"Authorization": "Token abc123"}


def test_bearer_missing_token_env(monkeypatch):
    monkeypatch.delenv("TEST_TOKEN", raising=False)
    with pytest.raises(AuthConfigError, match="TEST_TOKEN"):
        resolve_http_headers(
            "mcp",
            {"auth": {"type": "bearer", "token_env": "TEST_TOKEN"}},
        )


def test_bearer_missing_token_env_field():
    with pytest.raises(AuthConfigError, match="token_env"):
        resolve_http_headers("mcp", {"auth": {"type": "bearer"}})


def test_unknown_type():
    with pytest.raises(AuthConfigError, match=r"unsupported auth\.type"):
        resolve_http_headers("mcp", {"auth": {"type": "oauth"}})


def test_malformed_auth_not_dict():
    with pytest.raises(AuthConfigError, match="auth must be an object"):
        resolve_http_headers("mcp", {"auth": "bearer"})
