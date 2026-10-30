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
"""AC16 / TC-RS-016: two concurrent tenants never share a derived access token or data.

RoboShadow access tokens are exchanged lazily on each RoboShadowClient instance
(api_client.py) and a fresh client is built per request (server.py). There is no
module-level or shared cache, so isolation holds by construction; this test proves
it behaviourally, with two tenants' exchanges genuinely overlapping in time.
"""

import asyncio
import json

from roboshadow_mcp.api_client import RoboShadowClient, RoboShadowCredentials

from _fakes import build_server, call, make_handler


async def test_concurrent_tenants_never_share_access_token_or_data():
    mcp_a = build_server("tenant-a-refresh", handler=make_handler("tenant-a-refresh", org_name="Tenant A MSP", exchange_delay=0.05))
    mcp_b = build_server("tenant-b-refresh", handler=make_handler("tenant-b-refresh", org_name="Tenant B MSP", exchange_delay=0.05))

    result_a, result_b = await asyncio.gather(
        call(mcp_a, "roboshadow_list_organisations", {}),
        call(mcp_b, "roboshadow_list_organisations", {}),
    )

    org_a = json.loads(result_a)["items"][0]["name"]
    org_b = json.loads(result_b)["items"][0]["name"]
    assert org_a == "Tenant A MSP"
    assert org_b == "Tenant B MSP"


async def test_concurrent_access_token_exchanges_do_not_cross():
    client_a = RoboShadowClient(
        RoboShadowCredentials("tenant-a-refresh"),
        http_client=_http_client(make_handler("tenant-a-refresh", exchange_delay=0.05)),
    )
    client_b = RoboShadowClient(
        RoboShadowCredentials("tenant-b-refresh"),
        http_client=_http_client(make_handler("tenant-b-refresh", exchange_delay=0.05)),
    )

    token_a, token_b = await asyncio.gather(client_a._ensure_access_token(), client_b._ensure_access_token())
    assert token_a != token_b
    assert "tenant-a-refresh" not in token_b
    assert "tenant-b-refresh" not in token_a


def _http_client(handler):
    import httpx

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
