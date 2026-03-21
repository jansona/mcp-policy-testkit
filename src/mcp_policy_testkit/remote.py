from __future__ import annotations

import json
from urllib.request import Request, urlopen

from .models import ScanTarget, SourceLocation, ToolDefinition, ToolParameterSchema


def fetch_remote_target(url: str, timeout: int = 10) -> ScanTarget:
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = json.loads(response.read().decode("utf-8"))
    target = ScanTarget(target=url, mode="remote", metadata={"source_url": url})
    target.raw_documents.append((url, payload))
    tools = payload.get("tools", [])
    for index, tool in enumerate(tools):
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        target.tools.append(
            ToolDefinition(
                name=str(tool.get("name", f"remote_tool_{index}")),
                description=str(tool.get("description", "")),
                input_schema=ToolParameterSchema(
                    raw=schema if isinstance(schema, dict) else {},
                    required=schema.get("required", []) if isinstance(schema, dict) else [],
                ),
                metadata=tool,
                source=SourceLocation(
                    path=url,
                    pointer=f"/tools/{index}",
                    tool_name=str(tool.get("name", "")),
                ),
            )
        )
    return target
