# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Credential middleware: 401 on missing header, per-request isolation (AC15, AC16)."""

import asyncio

import pytest
from starlette.testclient import TestClient

from roboshadow_mcp.__main__ import build_http_app
from roboshadow_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# AC15 / TC-RS-015: missing header -> 401 listing the required header, not a 500.
@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_credential_header_returns_401_with_required_headers(value):
    headers = dict(MCP_HEADERS)
    if value is not None:
        headers["X-RoboShadow-Refresh-Token"] = value
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == ["X-RoboShadow-Refresh-Token"]


def test_tools_list_over_http_returns_every_tool():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | {"X-RoboShadow-Refresh-Token": "your-refresh-token"})
    assert resp.status_code == 200
    for name in ("roboshadow_list_organisations", "roboshadow_list_devices", "roboshadow_get_report", "roboshadow_get_mfa_report"):
        assert name in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_token_reaches_request_context_and_is_reset():
    seen = _run_middleware([(b"x-roboshadow-refresh-token", b"refresh-123")])
    assert seen["credentials"].refresh_token == "refresh-123"
    assert seen["client"].base_url == "https://api.roboshadow.com"
    assert _credentials_var.get() is None


def test_credentials_repr_hides_refresh_token():
    seen = _run_middleware([(b"x-roboshadow-refresh-token", b"secret-refresh-token")])
    assert "secret-refresh-token" not in repr(seen["credentials"])


async def test_concurrent_requests_through_real_middleware_never_leak_credentials():
    """AC16 / TC-RS-016 (review round 1 must-fix): two concurrent requests, both
    routed through the *same* GatewayCredentialsMiddleware instance and sharing
    the real module-level `_credentials_var`, must never see each other's
    refresh token -- not because two unrelated objects were built separately
    (tests/test_isolation.py's `build_server` bypasses this middleware entirely),
    but because the middleware's per-request ContextVar set/reset is correct
    under genuine concurrency.

    The delay lives inside the downstream ASGI app this middleware wraps, not
    inside a client built outside the middleware, so both requests are
    guaranteed to be in flight (both past their `_credentials_var.set`, neither
    past its `reset`) at the same time -- the exact window AC16 cares about.
    """
    overlap = {"in_flight": 0, "max_in_flight": 0}
    seen: dict[str, tuple[str | None, str | None]] = {}

    async def downstream_app(scope, receive, send):
        request_id = scope["app_request_id"]
        before = _credentials_var.get()
        overlap["in_flight"] += 1
        overlap["max_in_flight"] = max(overlap["max_in_flight"], overlap["in_flight"])
        await asyncio.sleep(0.05)  # yield control so the other request's set() can race in
        overlap["in_flight"] -= 1
        after = _credentials_var.get()
        seen[request_id] = (
            before.refresh_token if before else None,
            after.refresh_token if after else None,
        )
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayCredentialsMiddleware(downstream_app)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    async def one_request(request_id: str, token: str):
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-roboshadow-refresh-token", token.encode())],
            "app_request_id": request_id,
        }
        await middleware(scope, receive, send)

    await asyncio.gather(
        one_request("req-a", "tenant-a-refresh"),
        one_request("req-b", "tenant-b-refresh"),
    )

    # Both requests were genuinely in flight at once -- this is not a sequential run.
    assert overlap["max_in_flight"] == 2

    before_a, after_a = seen["req-a"]
    before_b, after_b = seen["req-b"]
    assert (before_a, after_a) == ("tenant-a-refresh", "tenant-a-refresh")
    assert (before_b, after_b) == ("tenant-b-refresh", "tenant-b-refresh")

    # Both finished; the shared ContextVar must be clean again, not stuck on
    # whichever request happened to reset() last.
    assert _credentials_var.get() is None
