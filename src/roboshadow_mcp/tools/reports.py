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
"""Organisation-level reports: antivirus, firewall, hardware, disks, updates, vulnerabilities,
remediation -- plus the CVE and remediation-attempt drill-downs.

Consolidated into one `roboshadow_get_report` tool with a `report` enum instead of mirroring
each of the 19 underlying vendor endpoints 1:1 (see "Tech design / Option analysis" in
docs/tickets/PRD-21238.md) to stay well under the platform's tool-count ceiling.
"""

from dataclasses import dataclass
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field as PydanticField

from ..api_client import RoboShadowClient
from ._common import READ_ONLY, ClientFactory, OrganisationId, Page, PageSize, page_params, paged_result, run_tool

Report = Literal[
    "antivirus_summary",
    "antivirus_by_device",
    "antivirus_ransomware",
    "antivirus_threats",
    "antivirus_windows_defender",
    "disks",
    "disks_by_device",
    "disks_summary",
    "firewalls",
    "hardware_by_device",
    "hardware_summary",
    "remediation",
    "updates_by_device",
    "updates_summary",
    "vulnerabilities_summary",
    "vulnerabilities_cves",
    "vulnerabilities_cpes",
    "vulnerabilities_applications",
    "vulnerabilities_devices",
]


@dataclass(frozen=True)
class _ReportSpec:
    suffix: str
    paged: bool
    days: bool = False
    search: bool = False
    sort: bool = False
    update_filters: bool = False  # critical/security/driver/rollup/other
    device_scope_filters: bool = False  # + workstations/servers/is_reboot_required


_REPORTS: dict[str, _ReportSpec] = {
    "antivirus_summary": _ReportSpec("antivirus/summary", paged=False),
    "antivirus_by_device": _ReportSpec("antivirus/bydevice", paged=True),
    "antivirus_ransomware": _ReportSpec("antivirus/ransomware", paged=True),
    "antivirus_threats": _ReportSpec("antivirus/threats", paged=True),
    "antivirus_windows_defender": _ReportSpec("antivirus/windowsdefenders", paged=True),
    "disks": _ReportSpec("disks", paged=True),
    "disks_by_device": _ReportSpec("disks/bydevice", paged=True),
    "disks_summary": _ReportSpec("disks/summary", paged=False),
    "firewalls": _ReportSpec("firewalls", paged=True),
    "hardware_by_device": _ReportSpec("hardware/bydevice", paged=True),
    "hardware_summary": _ReportSpec("hardware/summary", paged=False),
    "remediation": _ReportSpec("remediation-report", paged=True, search=True, days=True),
    "updates_by_device": _ReportSpec(
        "updates/bydevice", paged=True, sort=True, search=True, days=True, update_filters=True, device_scope_filters=True
    ),
    "updates_summary": _ReportSpec("updates/summary", paged=False, days=True),
    "vulnerabilities_summary": _ReportSpec("vulnerabilities/summary", paged=False, days=True),
    "vulnerabilities_cves": _ReportSpec("vulnerabilities/cves", paged=True, days=True),
    "vulnerabilities_cpes": _ReportSpec("vulnerabilities/cpes", paged=True),
    "vulnerabilities_applications": _ReportSpec("vulnerabilities/applications", paged=True, days=True),
    "vulnerabilities_devices": _ReportSpec("vulnerabilities/devices", paged=True, days=True),
}

AttemptId = Annotated[str, PydanticField(description="Remediation attempt id (from report='remediation').")]
CveId = Annotated[str, PydanticField(description="CVE id (from a vulnerabilities report, e.g. 'CVE-2024-12345').")]
Days = Annotated[int | None, PydanticField(description="Restrict to the last N days, where the report supports it.", ge=1)]
Search = Annotated[str | None, PydanticField(description="Case-insensitive substring filter, where the report supports it.")]
SortBy = Annotated[str | None, PydanticField(description="Field name to sort by, where the report supports it.")]
SortDesc = Annotated[bool | None, PydanticField(description="Sort descending, where the report supports it.")]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_report(
        organisation_id: OrganisationId,
        report: Annotated[Report, PydanticField(description="Which organisation-level report to return.")],
        page: Page = None,
        page_size: PageSize = None,
        days: Days = None,
        search: Search = None,
        sort_by: SortBy = None,
        sort_desc: SortDesc = None,
        critical: Annotated[bool | None, PydanticField(description="updates_by_device only: critical updates.")] = None,
        security: Annotated[bool | None, PydanticField(description="updates_by_device only: security updates.")] = None,
        driver: Annotated[bool | None, PydanticField(description="updates_by_device only: driver updates.")] = None,
        rollup: Annotated[bool | None, PydanticField(description="updates_by_device only: rollup updates.")] = None,
        other: Annotated[bool | None, PydanticField(description="updates_by_device only: other updates.")] = None,
        workstations: Annotated[bool | None, PydanticField(description="updates_by_device only: workstations.")] = None,
        servers: Annotated[bool | None, PydanticField(description="updates_by_device only: servers.")] = None,
        is_reboot_required: Annotated[bool | None, PydanticField(description="updates_by_device only: reboot-pending devices.")] = None,
    ) -> str:
        """Get an organisation-level security, hardware or vulnerability report.

        See the `report` enum for the 19 available reports and which filters apply to each.
        """

        spec = _REPORTS[report]
        path = f"/windows/organisation/{organisation_id}/reports/{spec.suffix}"

        async def action(client: RoboShadowClient) -> Any:
            if not spec.paged:
                params: dict[str, Any] = {}
                if spec.days and days is not None:
                    params["days"] = days
                return await client.get(path, params or None)

            params = page_params(page, page_size)
            if spec.days and days is not None:
                params["days"] = days
            if spec.search and search is not None:
                params["search"] = search
            if spec.sort:
                if sort_by is not None:
                    params["sortBy"] = sort_by
                if sort_desc is not None:
                    params["sortDesc"] = sort_desc
            if spec.update_filters:
                for key, value in (("critical", critical), ("security", security), ("driver", driver), ("rollup", rollup), ("other", other)):
                    if value is not None:
                        params[key] = value
            if spec.device_scope_filters:
                for key, value in (("workstations", workstations), ("servers", servers), ("isRebootRequired", is_reboot_required)):
                    if value is not None:
                        params[key] = value
            doc = await client.get(path, params)
            return paged_result(doc, params["itemsPerPage"])

        return await run_tool("roboshadow_get_report", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_remediation_cves(organisation_id: OrganisationId, attempt_id: AttemptId) -> str:
        """Get the CVEs addressed by one remediation attempt (from report='remediation')."""

        async def action(client: RoboShadowClient) -> Any:
            return await client.get(f"/windows/organisation/{organisation_id}/reports/remediation-report/{attempt_id}/cves")

        return await run_tool("roboshadow_get_remediation_cves", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def roboshadow_get_cve_fixes(organisation_id: OrganisationId, cve_id: CveId) -> str:
        """Get the fixes available for one CVE (from a vulnerabilities report)."""

        async def action(client: RoboShadowClient) -> dict[str, Any]:
            items = await client.get(f"/windows/organisation/{organisation_id}/reports/vulnerabilities/cves/{cve_id}/fixes") or []
            return {"items": items, "total": len(items)}

        return await run_tool("roboshadow_get_cve_fixes", client_factory, action)
