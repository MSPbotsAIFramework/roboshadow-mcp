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
"""Async client for the RoboShadow Rubicon Platform Data API.

Every call starts from a tenant's refresh token (the value of the
``X-RoboShadow-Refresh-Token`` header). The refresh token is exchanged for a
short-lived access token via ``POST /identity/bearertoken`` the first time
this client instance makes a call, and the access token is kept only on this
instance -- never in a module-level or cross-request cache (SOP SS3.3/SS3.4).
A fresh client is built per incoming request (see server.py), so the exchange
happens again on the next request even for the same tenant.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope
from .config import API_BASE_URL

logger = logging.getLogger("roboshadow_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own exchanged
# access token, so sharing the pool across tenants is safe.
_shared_http_client: httpx.AsyncClient | None = None


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT)
    return _shared_http_client


# status_code -> (error code, retryable), for calls against the data API
# (after the access token exchange has already succeeded). 0 means no HTTP
# response at all (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}

# status_code -> (error code, retryable), for the token-exchange call itself.
# Any 4xx there means the refresh token RoboShadow was given is bad, not that
# a request argument is bad -- so 400 maps to unauthorized here, unlike the
# data-call table above.
_EXCHANGE_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("unauthorized", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int, table: dict[int, tuple[str, bool]]) -> tuple[str, bool]:
    if status_code in table:
        return table[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


def classify_status(status_code: int) -> tuple[str, bool]:
    return _classify(status_code, _STATUS_TO_CODE)


class RoboShadowError(Exception):
    def __init__(self, status_code: int, message: str, *, during_exchange: bool = False):
        self.status_code = status_code
        self.message = message
        self.during_exchange = during_exchange
        super().__init__(f"RoboShadow API error {status_code}: {message}")

    def to_envelope(self) -> str:
        table = _EXCHANGE_STATUS_TO_CODE if self.during_exchange else _STATUS_TO_CODE
        code, retryable = _classify(self.status_code, table)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class RoboShadowCredentials:
    refresh_token: str

    def __repr__(self) -> str:  # never leak the refresh token into logs or tracebacks
        return "RoboShadowCredentials(refresh_token=<redacted>)"


class RoboShadowClient:
    """Thin wrapper over the RoboShadow API for one caller's refresh token.

    The access token is exchanged lazily (on the first call this instance
    makes) and cached only on ``self`` -- it never outlives this instance,
    and a new instance is built for every incoming request (server.py).
    """

    def __init__(self, credentials: RoboShadowCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.base_url = API_BASE_URL
        self._access_token = None

    async def _ensure_access_token(self) -> str:
        if self._access_token is None:
            self._access_token = await self._exchange()
        return self._access_token

    async def _exchange(self) -> str:
        http = self._http or _get_shared_http_client()
        url = f"{self.base_url}/identity/bearertoken"
        try:
            resp = await http.post(
                url,
                json={"refreshToken": self._credentials.refresh_token},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except httpx.TimeoutException as e:
            raise RoboShadowError(0, "Timed out exchanging the refresh token with RoboShadow", during_exchange=True) from e
        except httpx.RequestError as e:
            raise RoboShadowError(
                0, f"Network error exchanging the refresh token with RoboShadow: {type(e).__name__}", during_exchange=True
            ) from e
        if resp.status_code >= 400:
            raise RoboShadowError(resp.status_code, _error_message(resp, "RoboShadow rejected the refresh token"), during_exchange=True)
        body = _parse_body(resp) or {}
        token = body.get("accessToken") if isinstance(body, dict) else None
        if not token:
            raise RoboShadowError(resp.status_code or 0, "RoboShadow token exchange returned no accessToken", during_exchange=True)
        return token

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None) -> Any:
        access_token = await self._ensure_access_token()
        http = self._http or _get_shared_http_client()
        url = f"{self.base_url}{path}"
        query = {k: _param_value(v) for k, v in (params or {}).items() if v is not None}
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            try:
                resp = await http.request(method, url, params=query, headers=headers)
            except httpx.TimeoutException as e:
                status, error = 0, RoboShadowError(0, f"Timed out calling RoboShadow ({method} {path})")
                resp, exc = None, e
            except httpx.RequestError as e:
                status = 0
                error = RoboShadowError(0, f"Network error calling RoboShadow ({method} {path}): {type(e).__name__}")
                resp, exc = None, e
            else:
                status, error, exc = resp.status_code, None, None

            logger.info(
                "roboshadow_api method=%s path=%s status=%s ms=%d attempt=%d",
                method,
                path,
                status,
                (time.monotonic() - t0) * 1000,
                attempt,
            )

            retryable = status == 0 or status in _RETRYABLE_STATUS
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue

            if error is not None:
                raise error from exc
            assert resp is not None
            if resp.status_code >= 400:
                raise RoboShadowError(resp.status_code, _error_message(resp, "RoboShadow returned an error"))
            return _parse_body(resp)


def _param_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _error_message(resp: httpx.Response, fallback: str) -> str:
    """Short, credential-free description of a RoboShadow error response."""
    fallback = f"{fallback} (HTTP {resp.status_code})"
    try:
        payload = resp.json()
    except ValueError:
        return fallback
    if isinstance(payload, dict):
        for key in ("message", "error", "detail", "title"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return f"{fallback}: {value[:500]}"
    return fallback
