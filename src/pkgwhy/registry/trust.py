from __future__ import annotations

from pkgwhy.core.models import RegistryToolEntry, ToolTrustState
from pkgwhy.registry.local import current_registry, load_registry_index, save_registry_index
from pkgwhy.registry.tools import resolve_tool_entry


def set_tool_trust_state(reference: str, state: ToolTrustState) -> RegistryToolEntry:
    registry = current_registry()
    selected = resolve_tool_entry(reference, registry)
    index = load_registry_index(registry.path, strict=True)
    for entry in index.tools:
        if (
            entry.owner == selected.owner
            and entry.name == selected.name
            and entry.version == selected.version
        ):
            entry.trust_state = state
            save_registry_index(registry.path, index)
            return entry
    raise ValueError(f"Tool is not published in the current registry: {reference}")


def list_tools_by_trust_state(state: ToolTrustState) -> list[RegistryToolEntry]:
    registry = current_registry()
    index = load_registry_index(registry.path, strict=True)
    return sorted(
        (entry for entry in index.tools if entry.trust_state == state),
        key=lambda entry: (entry.owner, entry.name, entry.version),
    )
