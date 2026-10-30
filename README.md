# RoboShadow MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [RoboShadow](https://roboshadow.com) Rubicon
Platform Data API. It lets an AI agent review an MSP's endpoint security, asset inventory,
vulnerability and remediation-status data: organisations and their users, the device/asset
inventory, antivirus/firewall/Windows Defender posture, vulnerabilities (CVEs) and available fixes,
remediation attempts, OS update/patch compliance, Microsoft 365 MFA compliance, and external
vulnerability scan status.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: the refresh token arrives on every request as an HTTP header and is
  exchanged for a RoboShadow access token once per request, never stored; every tool is listed from
  the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-RoboShadow-Refresh-Token` | Yes | string | none | - | RoboShadow Firebase refresh token for the tenant's account. Exchanged by this server for a short-lived access token on every request; never cached. | `eyJhbGciOi...` |

Where to get it:

- In RoboShadow's own product, generate/export the account's Firebase refresh token (Settings ->
  API/Integrations in the RoboShadow back office; the exact menu path was not independently
  verified against a live account -- confirm with RoboShadow support if it has moved).
- One credential can see more than one organisation (tenant); call `roboshadow_list_organisations`
  to discover which ones.

A request to `/mcp` without the header gets HTTP 401 listing the required header.

## Tools

All tools return a JSON string and are read-only (`readOnlyHint: true`) -- the published RoboShadow
API has no write/action endpoint besides the internal token exchange, which is not itself exposed
as a tool. List-shaped tools take `page` (from 1) and `page_size` (default and max: see table) and
return `{items, total, has_more}` (or, where the vendor itself does not paginate, `{items, total}`).

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `roboshadow_list_organisations` | List the organisations visible to this credential | - |
| `roboshadow_list_organisation_users` | List one organisation's users | **organisation_id** |
| `roboshadow_list_devices` | List the device/asset inventory of an organisation | **organisation_id**, page, page_size (default 50, max 200), search, sort_by, sort_desc |
| `roboshadow_get_device` | One device's full summary record | **organisation_id**, **device_id** |
| `roboshadow_get_device_detail` | One device's antivirus / applications / disks / services / updates / user profiles / local users / vulnerability summary | **organisation_id**, **device_id**, **section** (`antivirus`, `applications`, `disks`, `services`, `updates`, `userprofiles`, `users`, `vulnerability_summary`), page, page_size, search, critical/security/driver/rollup/other (updates only) |
| `roboshadow_list_disk_shares` | Shares exposed on one disk of one device | **organisation_id**, **device_id**, **disk_id** |
| `roboshadow_list_application_groups` | List installed-application groups, or one group's device-level detail | **organisation_id**, group_id, page, page_size, search, sort_by, sort_desc |
| `roboshadow_get_report` | One of 19 organisation-level reports (see `report` enum) | **organisation_id**, **report**, page, page_size, days, search, sort_by, sort_desc, critical/security/driver/rollup/other/workstations/servers/is_reboot_required (updates_by_device only) |
| `roboshadow_get_remediation_cves` | CVEs addressed by one remediation attempt | **organisation_id**, **attempt_id** |
| `roboshadow_get_cve_fixes` | Fixes available for one CVE | **organisation_id**, **cve_id** |
| `roboshadow_list_vulnerability_scans` | Status of external vulnerability scans | **organisation_id**, page, page_size, sort_by, sort_desc, is_scheduled, status |
| `roboshadow_get_vulnerability_scan_summary` | One scan's summary | **organisation_id**, **scan_id** |
| `roboshadow_get_scanned_ips` | Scanned-IP overview for one scan | **organisation_id**, **scan_id** |
| `roboshadow_get_mfa_report` | Microsoft 365 MFA compliance report | **organisation_id**, page |

`report` enum for `roboshadow_get_report`: `antivirus_summary`, `antivirus_by_device`,
`antivirus_ransomware`, `antivirus_threats`, `antivirus_windows_defender`, `disks`,
`disks_by_device`, `disks_summary`, `firewalls`, `hardware_by_device`, `hardware_summary`,
`remediation`, `updates_by_device`, `updates_summary`, `vulnerabilities_summary`,
`vulnerabilities_cves`, `vulnerabilities_cpes`, `vulnerabilities_applications`,
`vulnerabilities_devices`.

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "RoboShadow rejected the refresh token (HTTP 401)", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. No rate limit is documented by RoboShadow; `429`/`5xx` responses
are retried with backoff respecting `Retry-After`.

## Run locally

```bash
uv sync
uv run python -m roboshadow_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t roboshadow-mcp:dev .
docker run --rm -p 8080:8080 roboshadow-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). The refresh token is never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-RoboShadow-Refresh-Token: your-refresh-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# list organisations
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-RoboShadow-Refresh-Token: your-refresh-token" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"roboshadow_list_organisations","arguments":{}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool consolidation (14 tools, not 40).** The vendor publishes 40 GET endpoints (plus the
  internal token-exchange POST). `roboshadow_get_report` covers 19 org-level report endpoints via a
  `report` enum, and `roboshadow_get_device_detail` covers 8 per-device sub-resource endpoints via a
  `section` enum, instead of mirroring each endpoint as its own tool -- see "Tech design / Option
  analysis" in `docs/tickets/PRD-21238.md`.
- **Field trimming.** List items are passed through largely as RoboShadow returns them, relying on
  the response-size cap (`dump_json_capped`, SS2.5) rather than a hand-picked field allowlist: the
  OpenAPI schema for `Device` (and several report schemas) has no live-verified field set (no test
  account was available -- see Risks in the tech design), so guessing a trimmed shape risked
  silently dropping or mis-keying a field an agent needs. This is a deliberate deviation from the
  tech design's illustrative trimmed-field example, recorded in the Self-test section.
- **Pagination.** Default 50 / hard cap 200 per tool call, overriding RoboShadow's own default
  10 / max 100 (SOP token-economy floor/ceiling; see "Decisions made by DEV01" in the ticket doc).
- **Credential exchange.** The refresh token is exchanged for an access token once per MCP request
  (lazily, on first vendor call that request makes) and never cached beyond that request -- see
  `api_client.py` and `tests/test_isolation.py`.
- **No write tools.** The published API has no write/action endpoint besides the internal token
  exchange, which is not itself exposed as a tool.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
