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


async def test_requests_interleaved_in_one_context_do_not_leak_credentials_across_overlap():
    """AC16 / TC-RS-016 (review round 2 must-fix on the round 1 fix,
    tests/test_middleware.py:95-159): the round 1 test drove two "requests" via
    `asyncio.gather`, which schedules each one as its own `asyncio.Task` --  and
    every `asyncio.Task` gets an *independently copied* `contextvars.Context` at
    creation. A `ContextVar.set()` performed inside one Task's copied context can
    never be observed by a sibling Task's copied context, so that test could not
    have failed even if `GatewayCredentialsMiddleware`'s
    `finally: _credentials_var.reset(...)` (server.py:105-107) were missing --
    verified empirically by commenting out both `.reset()` calls in the worktree
    and re-running the suite: all tests, including the round 1 one, stayed green
    (change not committed).

    This test drives both "requests" as plain coroutine objects stepped by hand
    with `.send(None)` -- no `asyncio.gather`, `asyncio.create_task`, or
    `asyncio.ensure_future` anywhere, hence no `asyncio.Task` and no context copy
    -- so both share the exact same `contextvars.Context` the way two requests
    processed by one long-lived worker/connection would. Request A's downstream
    app suspends at a bare `await asyncio.sleep(0)` checkpoint (CPython's
    `asyncio.sleep(0)` is a plain generator `yield` with no Future and no event
    loop involvement, so `.send(None)` drives it synchronously) after reading its
    own credentials but *before* `GatewayCredentialsMiddleware.__call__`'s
    `finally` resets them. Request B then runs to completion end-to-end in that
    same still-open context, and only then is request A resumed. If `.reset()`
    were missing or wrong, B's own `set()`/`reset()` pair would never restore
    A's pending value, and resuming A would observe B's leftover token instead
    of its own -- the exact cross-request leak AC16 forbids.
    """
    recorded: dict[str, str | None] = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    def scope_for(token: str) -> dict:
        return {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-roboshadow-refresh-token", token.encode())],
        }

    async def downstream_a(scope, receive, send):
        before = _credentials_var.get()
        recorded["a_before"] = before.refresh_token if before else None
        await asyncio.sleep(0)  # suspend here; request B runs to completion while we're paused
        after = _credentials_var.get()
        recorded["a_after"] = after.refresh_token if after else None
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def downstream_b(scope, receive, send):
        before = _credentials_var.get()
        recorded["b_before"] = before.refresh_token if before else None
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    coro_a = GatewayCredentialsMiddleware(downstream_a)(scope_for("tenant-a-refresh"), receive, send)
    coro_b = GatewayCredentialsMiddleware(downstream_b)(scope_for("tenant-b-refresh"), receive, send)

    assert _credentials_var.get() is None

    # Step A exactly once: this runs middleware A's `set()` and downstream_a up to
    # its `await asyncio.sleep(0)` checkpoint, then suspends -- a single `.send(None)`
    # advances a coroutine only to its *next* suspension point, never past it.
    # Middleware A's `finally` has NOT run yet: A's credentials are still live.
    coro_a.send(None)
    assert recorded["a_before"] == "tenant-a-refresh"
    assert "a_after" not in recorded, "request A ran to completion in one step; the pause point is broken"

    # Run B fully to completion in one `.send(None)` -- downstream_b never awaits
    # anything that suspends, so this one step runs middleware B start to finish,
    # in the exact same context (no Task was ever created for either request).
    with pytest.raises(StopIteration):
        coro_b.send(None)
    assert recorded["b_before"] == "tenant-b-refresh"

    # B's middleware reset the var back to whatever preceded B's own `set()` --
    # i.e. back to A's still-pending credentials, since A has not reset yet.
    still_pending = _credentials_var.get()
    assert still_pending is not None and still_pending.refresh_token == "tenant-a-refresh"

    # Resume A to completion. A leaking `GatewayCredentialsMiddleware` -- e.g. a
    # missing or misplaced `.reset()` -- would surface here as A observing B's token.
    with pytest.raises(StopIteration):
        coro_a.send(None)
    assert recorded["a_after"] == "tenant-a-refresh"

    # Both finished; the shared ContextVar must be clean again.
    assert _credentials_var.get() is None
