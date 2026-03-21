from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import (
    ConfigCommand,
    ScanTarget,
    SourceArtifact,
    SourceLocation,
    ToolDefinition,
    ToolParameterSchema,
)
from .utils import iter_candidate_files, json_pointer, load_data

TOOL_COLLECTION_KEYS = ("tools", "functions")
SOURCE_HINT_KEYS = ("source", "entrypoint", "script", "file", "module")
COMMAND_KEYS = ("command", "cmd", "shell", "run")


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
    _collect_source_hints(scan_target, path, document)


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
