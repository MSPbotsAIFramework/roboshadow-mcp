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
"""Shared argument types, result shaping and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import RoboShadowClient, RoboShadowError

logger = logging.getLogger("roboshadow_mcp.tools")

ClientFactory = Callable[[], RoboShadowClient | None]

# Design decision: the platform's token-economy floor/ceiling overrides RoboShadow's own
# defaults (page_size=10, max=100) -- see "Decisions made by DEV01" in docs/tickets/PRD-21238.md.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "RoboShadow credential is missing for this request (X-RoboShadow-Refresh-Token header).",
    False,
)

OrganisationId = Annotated[
    str, Field(description="RoboShadow organisation id (from roboshadow_list_organisations).")
]
DeviceId = Annotated[str, Field(description="RoboShadow device id (from roboshadow_list_devices).")]
Page = Annotated[int | None, Field(description="Page number, starting at 1 (default 1).", ge=1)]
PageSize = Annotated[
    int | None,
    Field(description=f"Items per page (default {DEFAULT_PAGE_SIZE}, max {MAX_PAGE_SIZE}).", ge=1),
]


def page_params(page: int | None, page_size: int | None, *, page_key: str = "page", size_key: str = "itemsPerPage") -> dict[str, Any]:
    size = DEFAULT_PAGE_SIZE if page_size is None else max(1, min(int(page_size), MAX_PAGE_SIZE))
    return {page_key: max(1, int(page or 1)), size_key: size}


def paged_result(document: Any, size: int | None = None) -> dict[str, Any]:
    """Shape a RoboShadow {pagedData, totalItems} envelope into {items, total, has_more}."""
    doc = document if isinstance(document, dict) else {}
    items = doc.get("pagedData") or []
    total = doc.get("totalItems")
    has_more = isinstance(total, int) and size is not None and len(items) == size and total > len(items)
    return {"items": items, "total": total, "has_more": bool(has_more)}


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[RoboShadowClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except RoboShadowError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
