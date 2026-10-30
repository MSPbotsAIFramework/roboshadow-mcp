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
"""Installed-application groups (organisation-level)."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import RoboShadowClient
from ._common import READ_ONLY, ClientFactory, OrganisationId, Page, PageSize, page_params, paged_result, run_tool

GroupId = Annotated[
    str | None,
    Field(description="Optional. An application group id (from a prior call with no group_id) to get its device-level detail."),
]
Search = Annotated[str | None, Field(description="Case-insensitive substring filter on application name.")]
SortBy = Annotated[str | None, Field(description="Field name to sort by.")]
SortDesc = Annotated[bool | None, Field(description="Sort descending (default ascending).")]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_list_application_groups(
        organisation_id: OrganisationId,
        group_id: GroupId = None,
        page: Page = None,
        page_size: PageSize = None,
        search: Search = None,
        sort_by: SortBy = None,
        sort_desc: SortDesc = None,
    ) -> str:
        """List installed-application groups for an organisation, or one group's device-level detail."""

        async def action(client: RoboShadowClient) -> Any:
            if group_id:
                return await client.get(f"/windows/organisation/{organisation_id}/applications/groups/{group_id}")
            params = page_params(page, page_size)
            if search is not None:
                params["search"] = search
            if sort_by is not None:
                params["sortBy"] = sort_by
            if sort_desc is not None:
                params["sortDesc"] = sort_desc
            doc = await client.get(f"/windows/organisation/{organisation_id}/applications/groups", params)
            return paged_result(doc, params["itemsPerPage"])

        return await run_tool("roboshadow_list_application_groups", client_factory, action)
