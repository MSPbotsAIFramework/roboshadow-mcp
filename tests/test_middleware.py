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
"""Credential middleware: 401 on missing header, per-request isolation (AC15)."""

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
