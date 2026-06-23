from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pkgwhy.core.models import ToolAgentPolicy, ToolManifest, ToolSecurityPolicy

MANIFEST_FILENAME = "pkgwhy.toml"


def read_tool_manifest(path: Path) -> ToolManifest:
    manifest_path = path / MANIFEST_FILENAME if path.is_dir() else path
    try:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Tool manifest not found: {manifest_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Tool manifest is not valid TOML: {manifest_path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read tool manifest: {manifest_path}") from exc

    return parse_tool_manifest_data(data)


def parse_tool_manifest_data(data: dict[str, Any]) -> ToolManifest:
    tool = _required_table(data, "tool")
    security = _optional_table(data, "security")
    agent = _optional_table(data, "agent")

    return ToolManifest(
        name=_required_text(tool, "name"),
        owner=_required_text(tool, "owner"),
        version=_required_text(tool, "version"),
        description=_required_text(tool, "description"),
        artifact_type=_required_text(tool, "artifact_type"),
        entrypoint=_required_text(tool, "entrypoint"),
        python_requires=_optional_text(tool, "python_requires", ">=3.11"),
        dependencies=_optional_text_list(tool, "dependencies"),
        declared_permissions=_optional_text_list(tool, "declared_permissions"),
        security=ToolSecurityPolicy.model_validate(security),
        agent=ToolAgentPolicy.model_validate(agent),
    )


def _required_table(data: dict[str, Any], key: str) -> dict[str, Any]:
    table = data.get(key)
    if not isinstance(table, dict):
        raise ValueError(f"Tool manifest must include a [{key}] table")
    return table


def _optional_table(data: dict[str, Any], key: str) -> dict[str, Any]:
    table = data.get(key, {})
    if not isinstance(table, dict):
        raise ValueError(f"Tool manifest [{key}] value must be a table")
    return table


def _required_text(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Tool manifest field is required and must be text: {key}")
    return value


def _optional_text(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Tool manifest field must be text when present: {key}")
    return value


def _optional_text_list(data: dict[str, Any], key: str) -> list[str]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"Tool manifest field must be a list of strings when present: {key}")
    return values
