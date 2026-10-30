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
"""Shared test helpers: a fake RoboShadow HTTP transport and a server built from it.

Not a test module itself (no test_ prefix), so pytest does not collect it.
"""

import asyncio
import json
from typing import Any

import httpx

from roboshadow_mcp._arguments import EnvelopeFastMCP
from roboshadow_mcp.api_client import RoboShadowClient, RoboShadowCredentials

ACCESS_TOKEN_FOR = {"good-refresh-token": "fake-access-token-a", "good-refresh-token-b": "fake-access-token-b"}

_DEVICES = [
    {
        "deviceName": f"PC-{i:02d}",
        "ipAddress": f"10.0.0.{i}",
        "isOnline": i % 2 == 0,
        "agentVersion": "1.2.3",
        "antiVirusScore": 90,
        "cvesCritical": 0,
        "cvesHigh": 1 if i % 3 == 0 else 0,
    }
    for i in range(1, 61)
]

_PAGED_REPORTS: dict[str, list[dict[str, Any]]] = {
    "/windows/organisation/org-1/reports/antivirus/bydevice": [{"deviceId": "dev-1", "status": "protected"}],
    "/windows/organisation/org-1/reports/antivirus/ransomware": [{"deviceId": "dev-1", "detected": False}],
    "/windows/organisation/org-1/reports/antivirus/threats": [{"deviceId": "dev-1", "threat": "none"}],
    "/windows/organisation/org-1/reports/antivirus/windowsdefenders": [{"deviceId": "dev-1", "enabled": True}],
    "/windows/organisation/org-1/reports/firewalls": [{"deviceId": "dev-1", "enabled": True}],
    "/windows/organisation/org-1/reports/hardware/bydevice": [{"deviceId": "dev-1", "cpu": "i7-1165G7"}],
    "/windows/organisation/org-1/reports/disks": [{"deviceId": "dev-1", "disk": "C"}],
    "/windows/organisation/org-1/reports/disks/bydevice": [{"deviceId": "dev-1", "disk": "C"}],
    "/windows/organisation/org-1/reports/remediation-report": [{"attemptId": "att-1", "status": "completed"}],
    "/windows/organisation/org-1/reports/vulnerabilities/cves": [{"cveId": "CVE-2024-12345", "cvss": 9.8}],
    "/windows/organisation/org-1/reports/vulnerabilities/cpes": [{"cpe": "cpe:2.3:a:vendor:app:1.0"}],
    "/windows/organisation/org-1/reports/vulnerabilities/applications": [{"appName": "App1", "cvss": 7.5}],
    "/windows/organisation/org-1/reports/vulnerabilities/devices": [{"deviceId": "dev-1", "cves": 3}],
}

_OBJECT_REPORTS: dict[str, dict[str, Any]] = {
    "/windows/organisation/org-1/reports/antivirus/summary": {"protected": 10, "unprotected": 2},
    "/windows/organisation/org-1/reports/hardware/summary": {"averageCpu": "i5-1135G7"},
    "/windows/organisation/org-1/reports/disks/summary": {"averageUsedPercentage": 55.0},
    "/windows/organisation/org-1/reports/updates/summary": {"missing": 3},
    "/windows/organisation/org-1/reports/vulnerabilities/summary": {"totalCriticalCves": 5, "devicesCritical": 2},
}


def _json(status_code: int, payload: Any) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def make_handler(valid_refresh_token: str = "good-refresh-token", *, org_name: str = "Acme MSP", exchange_delay: float = 0.0):
    """A fake RoboShadow transport. Exchanges ``valid_refresh_token`` for an access
    token and serves canned responses for every endpoint the tools call.

    ``org_name`` lets two fake tenants be told apart in isolation tests.
    ``exchange_delay`` forces the token exchange to await, so two concurrent
    requests are genuinely in flight at the same time instead of resolving
    sequentially fast enough to look concurrent by accident.
    """

    access_token = ACCESS_TOKEN_FOR.get(valid_refresh_token, f"fake-access-token-for-{valid_refresh_token}")

    async def handler(request: httpx.Request) -> httpx.Response:
        method, path, params = request.method, request.url.path, dict(request.url.params)

        if method == "POST" and path == "/identity/bearertoken":
            if exchange_delay:
                await asyncio.sleep(exchange_delay)
            body = json.loads(request.content or b"{}")
            if body.get("refreshToken") != valid_refresh_token:
                return _json(401, {"message": "Invalid refresh token"})
            return _json(200, {"accessToken": access_token, "expiresIn": 3600})

        if request.headers.get("authorization") != f"Bearer {access_token}":
            return _json(401, {"message": "Missing or invalid access token"})

        if path == "/identity/organisation":
            return _json(200, [{"id": "org-1", "name": org_name, "permissions": {"id": 1, "name": "Admin"}}])

        if path == "/identity/organisation/org-1/users":
            return _json(200, [{"displayName": "Jane Doe", "email": "jane@example.com", "permission": "Admin", "created": 1700000000}])
        if path == "/identity/organisation/org-forbidden/users":
            return _json(403, {"message": "This organisation is not visible to your credential"})

        if path == "/windows/organisation/org-1/device":
            devices = _DEVICES
            search = params.get("search")
            if search:
                devices = [d for d in devices if search in d["deviceName"]]
            if params.get("sortBy") == "deviceName" and params.get("sortDesc") == "true":
                devices = list(reversed(devices))
            size = int(params.get("itemsPerPage", 50))
            return _json(200, {"pagedData": devices[:size], "totalItems": len(devices)})

        if path == "/windows/organisation/org-1/device/dev-1":
            return _json(200, {"deviceName": "PC-01", "ipAddress": "10.0.0.1", "isOnline": True})
        if path == "/windows/organisation/org-1/device/dev-missing":
            return _json(404, {"message": "Device not found"})

        device_sections: dict[str, httpx.Response] = {
            "/windows/organisation/org-1/device/dev-1/antivirus": _json(200, {"antivirusName": "Defender", "isEnabled": True}),
            "/windows/organisation/org-1/device/dev-1/applications": _json(200, {"pagedData": [{"name": "Chrome", "version": "131.0"}], "totalItems": 1}),
            "/windows/organisation/org-1/device/dev-1/disks": _json(200, [{"id": "disk-1", "deviceLetter": "C", "freeSpace": 100, "size": 200, "usedPercentage": 50.0}]),
            "/windows/organisation/org-1/device/dev-1/report/vulnerabilities/summary": _json(200, {"summary": {"id": "dev-1", "critical": 1}, "applications": []}),
            "/windows/organisation/org-1/device/dev-1/services": _json(200, {"pagedData": [{"name": "svc1", "status": "running"}], "totalItems": 1}),
            "/windows/organisation/org-1/device/dev-1/updates": _json(200, {"pagedData": [{"title": "KB123", "critical": True}], "totalItems": 1}),
            "/windows/organisation/org-1/device/dev-1/userprofiles": _json(200, {"deviceId": "dev-1", "organisationId": "org-1", "userProfiles": [{"username": "jdoe"}]}),
            "/windows/organisation/org-1/device/dev-1/users": _json(200, {"deviceId": "dev-1", "organisationId": "org-1", "users": [{"username": "jdoe"}]}),
        }
        if path in device_sections:
            if path.endswith("/updates") and params.get("critical") == "true":
                return _json(200, {"pagedData": [{"title": "KB123", "critical": True}], "totalItems": 1})
            return device_sections[path]

        if path == "/windows/organisation/org-1/device/dev-1/disks/disk-1/shares":
            return _json(200, [{"name": "SharedDocs", "path": "C:\\Shared"}])

        if path == "/windows/organisation/org-1/applications/groups":
            return _json(200, {"pagedData": [{"applicationId": "app-1", "name": "Chrome", "deviceCount": 5, "count": 10, "vendor": "Google", "versions": 2}], "totalItems": 1})
        if path == "/windows/organisation/org-1/applications/groups/app-1":
            return _json(200, {"applicationId": "app-1", "name": "Chrome", "deviceCount": 5, "count": 10, "vendor": "Google", "versions": 2})

        if path in _PAGED_REPORTS:
            items = _PAGED_REPORTS[path]
            return _json(200, {"pagedData": items, "totalItems": len(items)})
        if path == "/windows/organisation/org-1/reports/updates/bydevice":
            items = [{"deviceId": "dev-1", "critical": True}]
            if params.get("critical") == "true":
                items = [i for i in items if i["critical"]]
            return _json(200, {"pagedData": items, "totalItems": len(items)})
        if path in _OBJECT_REPORTS:
            return _json(200, _OBJECT_REPORTS[path])

        if path == "/windows/organisation/org-1/reports/remediation-report/att-1/cves":
            return _json(200, {"cveIds": ["CVE-2024-12345"], "details": {}})
        if path == "/windows/organisation/org-1/reports/vulnerabilities/cves/CVE-2024-12345/fixes":
            return _json(200, [{"fixId": "fix-1", "availableVersion": "2.0", "description": "Upgrade to 2.0"}])

        if path == "/microsoft/report/mfa":
            return _json(200, {"hasMoreData": False, "securityDefaultsSetting": True, "users": [{"displayName": "Jane Doe", "mfaEnabled": True}]})

        if path == "/vscanner/scans/org-1/status":
            return _json(200, {"items": [{"scanId": "scan-1", "status": "completed"}], "total": 1})
        if path == "/vscanner/scans/org-1/summary/scan-1":
            return _json(200, {"ipSummary": {}, "scanDetails": {}, "webSummary": {}})
        if path == "/vscanner/scans/org-1/ips-overview/scan-1":
            return _json(200, [{"ipAddress": "1.2.3.4", "status": "completed"}])

        return _json(404, {"message": f"unhandled path in fake transport: {path}"})

    return handler


def build_server(refresh_token: str = "good-refresh-token", *, handler=None) -> EnvelopeFastMCP:
    """A FastMCP server whose tools are wired to a single fake-backed client.

    Bypasses the HTTP middleware entirely: the client_factory below always returns
    the same client, built directly with the test's refresh token and transport.
    """
    from roboshadow_mcp.server import INSTRUCTIONS
    from roboshadow_mcp.tools import applications, devices, mfa, organisations, reports, vulnerability_scanner

    transport = httpx.MockTransport(handler or make_handler(refresh_token))
    http_client = httpx.AsyncClient(transport=transport)
    client = RoboShadowClient(RoboShadowCredentials(refresh_token), http_client=http_client)

    mcp = EnvelopeFastMCP(name="roboshadow-mcp-test", instructions=INSTRUCTIONS)
    for module in (organisations, devices, applications, reports, mfa, vulnerability_scanner):
        module.register(mcp, lambda: client)
    return mcp


async def call(mcp: EnvelopeFastMCP, name: str, arguments: dict[str, Any]) -> str:
    content, _structured = await mcp.call_tool(name, arguments)
    return content[0].text
