from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import (
    ConfigCommand,
    PromptDefinition,
    RuntimeTarget,
    ScanTarget,
    SourceArtifact,
    SourceLocation,
    ToolDefinition,
    ToolParameterSchema,
)
from .utils import iter_candidate_files, json_pointer, load_data

TOOL_COLLECTION_KEYS = ("tools", "functions")
PROMPT_COLLECTION_KEYS = ("prompts",)
SOURCE_HINT_KEYS = ("source", "entrypoint", "script", "file", "module")
COMMAND_KEYS = ("command", "cmd", "shell", "run")
URL_KEYS = ("url", "serverUrl", "server_url", "endpoint")


def parse_target(target: str) -> ScanTarget:
    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    scan_target = ScanTarget(target=str(path), mode="local")
    for candidate in iter_candidate_files(path):
        if candidate.suffix.lower() in {".json", ".yaml", ".yml"}:
            data = load_data(candidate)
            scan_target.raw_documents.append((str(candidate), data))
            scan_target.configs.append(data)
            _extract_document(scan_target, candidate, data)
        elif candidate.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".sh"}:
            source_path = str(candidate.resolve())
            known_paths = {artifact.path for artifact in scan_target.source_artifacts}
            if source_path in known_paths:
                continue
            scan_target.source_artifacts.append(
                SourceArtifact(
                    path=source_path,
                    language=candidate.suffix.lower().lstrip("."),
                    content=candidate.read_text(encoding="utf-8"),
                )
            )
    return scan_target


def _extract_document(scan_target: ScanTarget, path: Path, document: dict[str, Any]) -> None:
    _collect_commands(scan_target, path, document)
    _collect_tools(scan_target, path, document)
    _collect_prompts(scan_target, path, document)
    _collect_source_hints(scan_target, path, document)
    _collect_runtime_targets(scan_target, path, document)


def _collect_tools(scan_target: ScanTarget, path: Path, document: dict[str, Any]) -> None:
    for key in TOOL_COLLECTION_KEYS:
        tools = document.get(key)
        if isinstance(tools, list):
            for index, tool in enumerate(tools):
                if not isinstance(tool, dict):
                    continue
                name = str(tool.get("name", f"unnamed_{index}"))
                schema = tool.get("inputSchema") or tool.get("input_schema") or {}
                required = schema.get("required", []) if isinstance(schema, dict) else []
                scan_target.tools.append(
                    ToolDefinition(
                        name=name,
                        description=str(tool.get("description", "")),
                        input_schema=ToolParameterSchema(
                            raw=schema if isinstance(schema, dict) else {},
                            required=[str(item) for item in required if isinstance(item, str)],
                        ),
                        metadata=tool,
                        source=SourceLocation(
                            path=str(path),
                            pointer=json_pointer(f"/{key}", str(index)),
                            tool_name=name,
                        ),
                    )
                )


def _collect_prompts(scan_target: ScanTarget, path: Path, document: dict[str, Any]) -> None:
    for key in PROMPT_COLLECTION_KEYS:
        prompts = document.get(key)
        if isinstance(prompts, list):
            for index, prompt in enumerate(prompts):
                if not isinstance(prompt, dict):
                    continue
                name = str(prompt.get("name", f"prompt_{index}"))
                scan_target.prompts.append(
                    PromptDefinition(
                        name=name,
                        description=str(prompt.get("description", "")),
                        arguments=prompt.get("arguments", []),
                        metadata=prompt,
                        source=SourceLocation(
                            path=str(path),
                            pointer=json_pointer(f"/{key}", str(index)),
                            tool_name=name,
                        ),
                    )
                )


def _collect_commands(scan_target: ScanTarget, path: Path, value: Any, pointer: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            next_pointer = json_pointer(pointer, str(key))
            if key in COMMAND_KEYS and isinstance(item, str):
                scan_target.commands.append(
                    ConfigCommand(
                        command=item,
                        source=SourceLocation(path=str(path), pointer=next_pointer),
                    )
                )
            _collect_commands(scan_target, path, item, next_pointer)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_commands(scan_target, path, item, json_pointer(pointer, str(index)))


def _collect_source_hints(scan_target: ScanTarget, path: Path, value: Any) -> None:
    if not isinstance(value, dict):
        return
    base = path.parent
    for key in SOURCE_HINT_KEYS:
        hint = value.get(key)
        if isinstance(hint, str):
            candidate = (base / hint).resolve()
            if candidate.exists() and candidate.is_file():
                artifact_path = str(candidate)
                known_paths = {artifact.path for artifact in scan_target.source_artifacts}
                if artifact_path not in known_paths:
                    scan_target.source_artifacts.append(
                        SourceArtifact(
                            path=artifact_path,
                            language=candidate.suffix.lower().lstrip("."),
                            content=candidate.read_text(encoding="utf-8"),
                        )
                    )
    for item in value.values():
        if isinstance(item, dict):
            _collect_source_hints(scan_target, path, item)
        elif isinstance(item, list):
            for child in item:
                if isinstance(child, dict):
                    _collect_source_hints(scan_target, path, child)


def _collect_runtime_targets(
    scan_target: ScanTarget,
    path: Path,
    value: Any,
    pointer: str = "",
    inherited_name: str = "",
) -> None:
    if isinstance(value, dict):
        runtime_name = str(value.get("name", inherited_name or ""))
        collection_keys = TOOL_COLLECTION_KEYS + PROMPT_COLLECTION_KEYS
        is_manifest_like = any(key in value for key in collection_keys)
        if not is_manifest_like and any(key in value for key in URL_KEYS):
            url = next((value[key] for key in URL_KEYS if isinstance(value.get(key), str)), None)
            if url:
                _append_runtime_target(
                    scan_target,
                    RuntimeTarget(
                        transport=str(value.get("transport", "http")),
                        name=runtime_name,
                        url=url,
                        source=SourceLocation(path=str(path), pointer=pointer or "/"),
                    ),
                )
        if not is_manifest_like and isinstance(value.get("command"), str) and "args" in value:
            args = value.get("args", [])
            env = value.get("env", {})
            cwd = value.get("cwd")
            _append_runtime_target(
                scan_target,
                RuntimeTarget(
                    transport="stdio",
                    name=runtime_name,
                    command=value["command"],
                    args=[str(item) for item in args] if isinstance(args, list) else [],
                    cwd=str((path.parent / cwd).resolve()) if isinstance(cwd, str) else None,
                    env={str(key): str(item) for key, item in env.items()}
                    if isinstance(env, dict)
                    else {},
                    source=SourceLocation(path=str(path), pointer=pointer or "/"),
                ),
            )
        for key, item in value.items():
            next_pointer = json_pointer(pointer, str(key))
            next_name = runtime_name if runtime_name else str(key)
            _collect_runtime_targets(scan_target, path, item, next_pointer, next_name)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_runtime_targets(
                scan_target,
                path,
                item,
                json_pointer(pointer, str(index)),
                inherited_name,
            )


def _append_runtime_target(scan_target: ScanTarget, runtime_target: RuntimeTarget) -> None:
    fingerprint = (
        runtime_target.transport,
        runtime_target.command,
        tuple(runtime_target.args),
        runtime_target.cwd,
        runtime_target.url,
    )
    known = {
        (
            item.transport,
            item.command,
            tuple(item.args),
            item.cwd,
            item.url,
        )
        for item in scan_target.runtime_targets
    }
    if fingerprint not in known:
        scan_target.runtime_targets.append(runtime_target)
