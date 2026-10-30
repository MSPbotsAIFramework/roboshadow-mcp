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
"""Devices (asset inventory) and their per-device sub-resources."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import RoboShadowClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    DeviceId,
    OrganisationId,
    Page,
    PageSize,
    page_params,
    paged_result,
    run_tool,
)

Search = Annotated[str | None, Field(description="Case-insensitive substring filter on device name.")]
SortBy = Annotated[str | None, Field(description="Field name to sort by.")]
SortDesc = Annotated[bool | None, Field(description="Sort descending (default ascending).")]
DiskId = Annotated[str, Field(description="Disk id (from the device's disk list, section='disks').")]

Section = Literal[
    "antivirus",
    "applications",
    "disks",
    "services",
    "updates",
    "userprofiles",
    "users",
    "vulnerability_summary",
]

# section -> (path suffix, paged?). "paged" sections accept page/page_size/search;
# device updates accepts the same boolean filters as the org-level updates_by_device report.
_SECTIONS: dict[str, tuple[str, bool]] = {
    "antivirus": ("antivirus", False),
    "applications": ("applications", True),
    "disks": ("disks", False),
    "services": ("services", True),
    "updates": ("updates", True),
    "userprofiles": ("userprofiles", False),
    "users": ("users", False),
    "vulnerability_summary": ("report/vulnerabilities/summary", False),
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_list_devices(
        organisation_id: OrganisationId,
        page: Page = None,
        page_size: PageSize = None,
        search: Search = None,
        sort_by: SortBy = None,
        sort_desc: SortDesc = None,
    ) -> str:
        """List the devices (asset inventory) of one organisation, with online state, AV score and CVE counts."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            params = page_params(page, page_size)
            if search is not None:
                params["search"] = search
            if sort_by is not None:
                params["sortBy"] = sort_by
            if sort_desc is not None:
                params["sortDesc"] = sort_desc
            doc = await client.get(f"/windows/organisation/{organisation_id}/device", params)
            return paged_result(doc, params["itemsPerPage"])

        return await run_tool("roboshadow_list_devices", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_device(organisation_id: OrganisationId, device_id: DeviceId) -> str:
        """Get one device's full summary record (hardware, OS, scores, CVE counts)."""

        async def action(client: RoboShadowClient) -> Any:
            return await client.get(f"/windows/organisation/{organisation_id}/device/{device_id}")

        return await run_tool("roboshadow_get_device", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_device_detail(
        organisation_id: OrganisationId,
        device_id: DeviceId,
        section: Annotated[Section, Field(description="Which per-device sub-resource to return.")],
        page: Page = None,
        page_size: PageSize = None,
        search: Search = None,
        critical: Annotated[bool | None, Field(description="updates section only: critical updates.")] = None,
        security: Annotated[bool | None, Field(description="updates section only: security updates.")] = None,
        driver: Annotated[bool | None, Field(description="updates section only: driver updates.")] = None,
        rollup: Annotated[bool | None, Field(description="updates section only: rollup updates.")] = None,
        other: Annotated[bool | None, Field(description="updates section only: other updates.")] = None,
    ) -> str:
        """Get one device's antivirus, apps, disks, services, updates, users or vulnerability summary.

        Section-specific args: applications/services take `search`; updates also takes
        critical/security/driver/rollup/other booleans.
        """

        suffix, is_paged = _SECTIONS[section]
        base = f"/windows/organisation/{organisation_id}/device/{device_id}/{suffix}"

        async def action(client: RoboShadowClient) -> Any:
            if not is_paged:
                return await client.get(base)
            params = page_params(page, page_size)
            if search is not None and section in ("applications", "services"):
                params["search"] = search
            if section == "updates":
                for key, value in (("critical", critical), ("security", security), ("driver", driver), ("rollup", rollup), ("other", other)):
                    if value is not None:
                        params[key] = value
            doc = await client.get(base, params)
            return paged_result(doc, params["itemsPerPage"])

        return await run_tool("roboshadow_get_device_detail", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_list_disk_shares(organisation_id: OrganisationId, device_id: DeviceId, disk_id: DiskId) -> str:
        """List the shares exposed on one disk of one device."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            items = await client.get(f"/windows/organisation/{organisation_id}/device/{device_id}/disks/{disk_id}/shares") or []
            return {"items": items, "total": len(items)}

        return await run_tool("roboshadow_list_disk_shares", client_factory, action)
