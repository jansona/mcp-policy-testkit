from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from .models import (
    PromptDefinition,
    RuntimeTarget,
    ScanTarget,
    SourceLocation,
    ToolDefinition,
    ToolParameterSchema,
)


class MCPHandshakeError(RuntimeError):
    """Raised when an MCP transport cannot complete initialization."""


class JsonRpcClient:
    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return


class HttpJsonRpcClient(JsonRpcClient):
    def __init__(self, url: str, timeout: int = 10) -> None:
        self.url = url
        self.timeout = timeout
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        self._next_id += 1
        if params is not None:
            payload["params"] = params
        request = Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            message = json.loads(response.read().decode("utf-8"))
        return _extract_result(message, method)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        request = Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout):  # noqa: S310
            return


class StdioJsonRpcClient(JsonRpcClient):
    def __init__(self, runtime_target: RuntimeTarget, timeout: int = 10) -> None:
        if not runtime_target.command:
            raise MCPHandshakeError("Missing command for stdio runtime target.")
        env = os.environ.copy()
        env.update(runtime_target.env)
        self.timeout = timeout
        self._next_id = 1
        self.process = subprocess.Popen(
            [runtime_target.command, *runtime_target.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=runtime_target.cwd,
            env=env,
            bufsize=1,
        )
        if not self.process.stdin or not self.process.stdout:
            raise MCPHandshakeError("Failed to open stdio pipes for MCP server.")

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": message_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)
        while True:
            response = self._read_message()
            if response.get("id") == message_id:
                return _extract_result(response, method)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def _write_message(self, payload: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def _read_message(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            stderr = ""
            if self.process.stderr is not None:
                stderr = self.process.stderr.read().strip()
            raise MCPHandshakeError(
                "MCP stdio server closed the connection before replying."
                + (f" stderr={stderr}" if stderr else "")
            )
        return json.loads(line)


def fetch_remote_target(url: str, timeout: int = 10) -> ScanTarget:
    if url.startswith("file://"):
        return _load_metadata_file(url)
    runtime_target = RuntimeTarget(
        transport="http",
        url=url,
        source=SourceLocation(path=url, pointer="/"),
    )
    return fetch_runtime_target(runtime_target, timeout=timeout)


def fetch_runtime_target(runtime_target: RuntimeTarget, timeout: int = 10) -> ScanTarget:
    if runtime_target.transport == "stdio":
        client: JsonRpcClient = StdioJsonRpcClient(runtime_target, timeout=timeout)
        target_name = runtime_target.name or runtime_target.command or "stdio-target"
    elif runtime_target.url:
        client = HttpJsonRpcClient(runtime_target.url, timeout=timeout)
        target_name = runtime_target.name or runtime_target.url
    else:
        raise MCPHandshakeError("Runtime target does not define a usable transport.")

    try:
        return _handshake_and_collect(client, runtime_target, target_name)
    finally:
        client.close()


def _handshake_and_collect(
    client: JsonRpcClient,
    runtime_target: RuntimeTarget,
    target_name: str,
) -> ScanTarget:
    initialize_result = client.request(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {
                "tools": {"listChanged": True},
                "prompts": {"listChanged": True},
            },
            "clientInfo": {
                "name": "mcp-policy-testkit",
                "version": "0.1.0",
            },
        },
    )
    client.notify("notifications/initialized")

    target = ScanTarget(
        target=target_name,
        mode="remote",
        metadata={
            "runtime_transport": runtime_target.transport,
            "server_info": initialize_result.get("serverInfo", {}),
            "protocol_version": initialize_result.get("protocolVersion"),
            "instructions": initialize_result.get("instructions"),
        },
    )
    _collect_tools_via_pagination(client, runtime_target, target)
    _collect_prompts_via_pagination(client, runtime_target, target)
    return target


def _collect_tools_via_pagination(
    client: JsonRpcClient,
    runtime_target: RuntimeTarget,
    target: ScanTarget,
) -> None:
    cursor = None
    tool_index = 0
    while True:
        params = {"cursor": cursor} if cursor else {}
        result = client.request("tools/list", params)
        for tool in result.get("tools", []):
            schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            name = str(tool.get("name", f"remote_tool_{tool_index}"))
            target.tools.append(
                ToolDefinition(
                    name=name,
                    description=str(tool.get("description", "")),
                    input_schema=ToolParameterSchema(
                        raw=schema if isinstance(schema, dict) else {},
                        required=schema.get("required", []) if isinstance(schema, dict) else [],
                    ),
                    metadata=tool,
                    source=runtime_target.source.model_copy(
                        update={"pointer": f"/tools/{tool_index}", "tool_name": name}
                    ),
                )
            )
            tool_index += 1
        cursor = result.get("nextCursor")
        if not cursor:
            break


def _collect_prompts_via_pagination(
    client: JsonRpcClient,
    runtime_target: RuntimeTarget,
    target: ScanTarget,
) -> None:
    cursor = None
    prompt_index = 0
    while True:
        try:
            params = {"cursor": cursor} if cursor else {}
            result = client.request("prompts/list", params)
        except MCPHandshakeError:
            break
        for prompt in result.get("prompts", []):
            name = str(prompt.get("name", f"remote_prompt_{prompt_index}"))
            target.prompts.append(
                PromptDefinition(
                    name=name,
                    description=str(prompt.get("description", "")),
                    arguments=prompt.get("arguments", []),
                    metadata=prompt,
                    source=runtime_target.source.model_copy(
                        update={"pointer": f"/prompts/{prompt_index}", "tool_name": name}
                    ),
                )
            )
            prompt_index += 1
        cursor = result.get("nextCursor")
        if not cursor:
            break


def _extract_result(message: dict[str, Any], method: str) -> dict[str, Any]:
    if "error" in message:
        error = message["error"]
        raise MCPHandshakeError(f"{method} failed: {error}")
    result = message.get("result")
    if not isinstance(result, dict):
        raise MCPHandshakeError(f"{method} returned a non-object result.")
    return result


def _load_metadata_file(url: str) -> ScanTarget:
    path = Path(url.removeprefix("file://"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    target = ScanTarget(
        target=url,
        mode="remote",
        metadata={"source_url": url, "mode": "metadata_file"},
    )
    target.raw_documents.append((url, payload))
    for index, tool in enumerate(payload.get("tools", [])):
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
    for index, prompt in enumerate(payload.get("prompts", [])):
        target.prompts.append(
            PromptDefinition(
                name=str(prompt.get("name", f"remote_prompt_{index}")),
                description=str(prompt.get("description", "")),
                arguments=prompt.get("arguments", []),
                metadata=prompt,
                source=SourceLocation(
                    path=url,
                    pointer=f"/prompts/{index}",
                    tool_name=str(prompt.get("name", "")),
                ),
            )
        )
    return target
