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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import RoboShadowClient, RoboShadowCredentials
from .config import Settings

HEADER_REFRESH_TOKEN = "X-RoboShadow-Refresh-Token"
REQUIRED_HEADERS = [HEADER_REFRESH_TOKEN]
OPTIONAL_HEADERS: list[str] = []

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level. The access token is exchanged separately, lazily,
# on the RoboShadowClient instance built from these credentials -- never here.
_credentials_var: contextvars.ContextVar[RoboShadowCredentials | None] = contextvars.ContextVar(
    "roboshadow_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("roboshadow_request_id", default="-")

INSTRUCTIONS = (
    "RoboShadow is an endpoint security and vulnerability management platform for MSPs: "
    "asset inventory, antivirus/firewall/Defender posture, CVE tracking, remediation/patch "
    "status, Microsoft 365 MFA compliance, and external vulnerability scanning. An "
    "organisation is one managed tenant; a credential can see more than one, so call "
    "roboshadow_list_organisations first to get a valid organisation_id.\n"
    "Typical flows:\n"
    "- Assets: roboshadow_list_devices -> roboshadow_get_device / "
    "roboshadow_get_device_detail(section=...).\n"
    "- Security posture: roboshadow_get_report(report='antivirus_*'|'firewalls').\n"
    "- Vulnerabilities: roboshadow_get_report(report='vulnerabilities_*') -> "
    "roboshadow_get_cve_fixes.\n"
    "- Remediation: roboshadow_get_report(report='remediation') -> "
    "roboshadow_get_remediation_cves.\n"
    "- Patch compliance: roboshadow_get_report(report='updates_by_device'|'updates_summary').\n"
    "- Hardware/disks: roboshadow_get_report(report='hardware_*'|'disks*').\n"
    "- MFA: roboshadow_get_mfa_report. External scans: "
    "roboshadow_list_vulnerability_scans -> roboshadow_get_vulnerability_scan_summary / "
    "roboshadow_get_scanned_ips.\n"
    "All tools are read-only. Lists use page / page_size (default 50, max 200) and return "
    "{items, total, has_more}."
)


def get_client_from_context() -> RoboShadowClient | None:
    """The RoboShadow client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return RoboShadowClient(credentials)


class GatewayCredentialsMiddleware:
    """Reads X-RoboShadow-Refresh-Token on /mcp requests into the request context; 401 when missing."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        refresh_token = (request.headers.get(HEADER_REFRESH_TOKEN) or "").strip()
        if not refresh_token:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Required header missing: {HEADER_REFRESH_TOKEN}",
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": OPTIONAL_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(RoboShadowCredentials(refresh_token))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every RoboShadow tool."""
    mcp = EnvelopeFastMCP(
        name="roboshadow-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], RoboShadowClient | None] = get_client_from_context

    from .tools import applications, devices, mfa, organisations, reports, vulnerability_scanner

    for module in (organisations, devices, applications, reports, mfa, vulnerability_scanner):
        module.register(mcp, client_factory)

    return mcp
