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
"""tools/list snapshot, error-envelope mapping, and per-tool behaviour against a fake transport."""

import asyncio
import json

import pytest

from roboshadow_mcp.api_client import RoboShadowError
from roboshadow_mcp.server import INSTRUCTIONS, create_mcp_server

from _fakes import build_server, call

# Tool names and required params are a public contract (SOP SS13): changing this
# snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "roboshadow_list_organisations": set(),
    "roboshadow_list_organisation_users": {"organisation_id"},
    "roboshadow_list_devices": {"organisation_id"},
    "roboshadow_get_device": {"organisation_id", "device_id"},
    "roboshadow_get_device_detail": {"organisation_id", "device_id", "section"},
    "roboshadow_list_disk_shares": {"organisation_id", "device_id", "disk_id"},
    "roboshadow_list_application_groups": {"organisation_id"},
    "roboshadow_get_report": {"organisation_id", "report"},
    "roboshadow_get_remediation_cves": {"organisation_id", "attempt_id"},
    "roboshadow_get_cve_fixes": {"organisation_id", "cve_id"},
    "roboshadow_list_vulnerability_scans": {"organisation_id"},
    "roboshadow_get_vulnerability_scan_summary": {"organisation_id", "scan_id"},
    "roboshadow_get_scanned_ips": {"organisation_id", "scan_id"},
    "roboshadow_get_mfa_report": {"organisation_id"},
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tools_list_snapshot(tools):
    # AC1/AC-adjacent (TC-RS-017): exactly the 14 roboshadow_* tools, all read-only.
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_all_tools_are_read_only(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


def test_instructions_present_and_bounded():
    assert INSTRUCTIONS and len(INSTRUCTIONS) <= 1500
    for name in ("roboshadow_list_organisations", "roboshadow_list_devices", "roboshadow_get_report"):
        assert name in INSTRUCTIONS


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    envelope = json.loads(RoboShadowError(status_code, "boom").to_envelope())
    assert envelope == {"error": {"code": expected_code, "message": "boom", "retryable": expected_retryable}}


# --- AC1 / TC-RS-001 -----------------------------------------------------------
async def test_list_organisations_returns_visible_orgs():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_organisations", {}))
    assert result["total"] == 1
    assert result["items"][0]["id"] == "org-1"


# --- AC2 / TC-RS-002 ------------------------------------------------------------
async def test_list_organisation_users_returns_users():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_organisation_users", {"organisation_id": "org-1"}))
    assert result["total"] == 1
    assert result["items"][0]["email"] == "jane@example.com"


async def test_list_organisation_users_maps_403_to_unauthorized():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_organisation_users", {"organisation_id": "org-forbidden"}))
    assert result["error"]["code"] == "unauthorized"


# --- AC3 / TC-RS-003 ------------------------------------------------------------
async def test_list_devices_default_page_has_more():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_devices", {"organisation_id": "org-1"}))
    assert len(result["items"]) == 50  # default page size
    assert result["total"] == 60
    assert result["has_more"] is True


async def test_list_devices_search_and_sort_filters():
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_list_devices", {"organisation_id": "org-1", "search": "PC-05", "sort_by": "deviceName", "sort_desc": True})
    )
    assert all("PC-05" in item["deviceName"] for item in result["items"])


# --- AC4 / TC-RS-004 ------------------------------------------------------------
async def test_get_device_returns_summary():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_device", {"organisation_id": "org-1", "device_id": "dev-1"}))
    assert result["deviceName"] == "PC-01"


async def test_get_device_unknown_id_returns_not_found():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_device", {"organisation_id": "org-1", "device_id": "dev-missing"}))
    assert result["error"]["code"] == "not_found"


# --- AC5 / TC-RS-005 ------------------------------------------------------------
@pytest.mark.parametrize(
    "section,key",
    [
        ("antivirus", "antivirusName"),
        ("applications", "items"),
        ("services", "items"),
        ("updates", "items"),
        ("userprofiles", "userProfiles"),
        ("users", "users"),
        ("vulnerability_summary", "summary"),
    ],
)
async def test_get_device_detail_all_sections(section, key):
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_get_device_detail", {"organisation_id": "org-1", "device_id": "dev-1", "section": section})
    )
    assert "error" not in result
    assert key in result


async def test_get_device_detail_disks_section_returns_raw_vendor_array():
    # The vendor's own /disks endpoint is unpaginated and returns a plain array
    # (unlike applications/services/updates, which are {pagedData, totalItems}).
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_get_device_detail", {"organisation_id": "org-1", "device_id": "dev-1", "section": "disks"})
    )
    assert isinstance(result, list)
    assert result[0]["deviceLetter"] == "C"


# --- AC6 / TC-RS-006 ------------------------------------------------------------
async def test_list_disk_shares_returns_shares():
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_list_disk_shares", {"organisation_id": "org-1", "device_id": "dev-1", "disk_id": "disk-1"})
    )
    assert result["items"][0]["name"] == "SharedDocs"


# --- AC7 / TC-RS-007 ------------------------------------------------------------
async def test_list_application_groups_returns_groups():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_application_groups", {"organisation_id": "org-1"}))
    assert result["items"][0]["applicationId"] == "app-1"


async def test_list_application_groups_detail_for_group_id():
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_list_application_groups", {"organisation_id": "org-1", "group_id": "app-1"})
    )
    assert result["name"] == "Chrome"
    assert result["deviceCount"] == 5


# --- AC8 / TC-RS-008 -------------------------------------------------------------
@pytest.mark.parametrize(
    "report",
    ["antivirus_summary", "antivirus_by_device", "antivirus_ransomware", "antivirus_threats", "antivirus_windows_defender", "firewalls"],
)
async def test_get_report_antivirus_and_firewall_variants(report):
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": report}))
    assert "error" not in result


# --- AC9 / TC-RS-009 --------------------------------------------------------------
@pytest.mark.parametrize(
    "report", ["vulnerabilities_summary", "vulnerabilities_cves", "vulnerabilities_cpes", "vulnerabilities_applications", "vulnerabilities_devices"]
)
async def test_get_report_vulnerability_variants(report):
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": report}))
    assert "error" not in result


async def test_get_cve_fixes_returns_fixes():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_cve_fixes", {"organisation_id": "org-1", "cve_id": "CVE-2024-12345"}))
    assert result["items"][0]["fixId"] == "fix-1"


# --- AC10 / TC-RS-010 --------------------------------------------------------------
async def test_get_report_remediation():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": "remediation"}))
    assert result["items"][0]["attemptId"] == "att-1"


async def test_get_remediation_cves_returns_cves():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_remediation_cves", {"organisation_id": "org-1", "attempt_id": "att-1"}))
    assert result["cveIds"] == ["CVE-2024-12345"]


# --- AC11 / TC-RS-011 ---------------------------------------------------------------
@pytest.mark.parametrize("report", ["updates_by_device", "updates_summary"])
async def test_get_report_updates_variants(report):
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": report}))
    assert "error" not in result


async def test_get_report_updates_by_device_filters():
    mcp = build_server()
    result = json.loads(
        await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": "updates_by_device", "critical": True})
    )
    assert all(item["critical"] for item in result["items"])


# --- AC12 / TC-RS-012 -----------------------------------------------------------------
@pytest.mark.parametrize("report", ["hardware_by_device", "hardware_summary", "disks", "disks_by_device", "disks_summary"])
async def test_get_report_hardware_and_disk_variants(report):
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_report", {"organisation_id": "org-1", "report": report}))
    assert "error" not in result


# --- AC13 / TC-RS-013 -----------------------------------------------------------------
async def test_get_mfa_report_returns_report():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_get_mfa_report", {"organisation_id": "org-1"}))
    assert result["items"][0]["displayName"] == "Jane Doe"
    assert result["security_defaults_enabled"] is True


# --- AC14 / TC-RS-014 -----------------------------------------------------------------
async def test_list_vulnerability_scans_returns_status():
    mcp = build_server()
    result = json.loads(await call(mcp, "roboshadow_list_vulnerability_scans", {"organisation_id": "org-1"}))
    assert result["items"][0]["scanId"] == "scan-1"


async def test_get_vulnerability_scan_summary_and_scanned_ips():
    mcp = build_server()
    summary = json.loads(await call(mcp, "roboshadow_get_vulnerability_scan_summary", {"organisation_id": "org-1", "scan_id": "scan-1"}))
    assert "ipSummary" in summary
    ips = json.loads(await call(mcp, "roboshadow_get_scanned_ips", {"organisation_id": "org-1", "scan_id": "scan-1"}))
    assert ips["items"][0]["ipAddress"] == "1.2.3.4"
