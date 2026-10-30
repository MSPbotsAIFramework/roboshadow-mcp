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
"""Microsoft 365 MFA compliance report."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..api_client import RoboShadowClient
from ._common import READ_ONLY, ClientFactory, OrganisationId, Page, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_mfa_report(organisation_id: OrganisationId, page: Page = None) -> str:
        """Get the Microsoft 365 MFA compliance report RoboShadow has for an organisation's users."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            params: dict[str, Any] = {"organisationId": organisation_id}
            if page is not None:
                params["skipPages"] = max(0, int(page) - 1)
            doc = await client.get("/microsoft/report/mfa", params) or {}
            return {
                "items": doc.get("users") or [],
                "has_more": bool(doc.get("hasMoreData")),
                "security_defaults_enabled": doc.get("securityDefaultsSetting"),
            }

        return await run_tool("roboshadow_get_mfa_report", client_factory, action)
