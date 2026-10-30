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
"""Organisations and their users (RoboShadow calls a managed tenant an "organisation")."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..api_client import RoboShadowClient
from ._common import READ_ONLY, ClientFactory, OrganisationId, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_list_organisations() -> str:
        """List the organisations (tenants) visible to this credential, with id, name and permission level."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            items = await client.get("/identity/organisation") or []
            return {"items": items, "total": len(items)}

        return await run_tool("roboshadow_list_organisations", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_list_organisation_users(organisation_id: OrganisationId) -> str:
        """List the users of one organisation (display name, email, permission level)."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            items = await client.get(f"/identity/organisation/{organisation_id}/users") or []
            return {"items": items, "total": len(items)}

        return await run_tool("roboshadow_list_organisation_users", client_factory, action)
