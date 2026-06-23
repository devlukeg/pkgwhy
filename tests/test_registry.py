from pathlib import Path

from pkgwhy.registry.local import (
    REGISTRY_INDEX_FILENAME,
    add_registry,
    config_path,
    init_local_registry,
    list_registries,
    load_registry_config,
    use_registry,
)


def test_init_local_registry_creates_index_and_selects_registry(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    registry_path = tmp_path / "registry"

    entry = init_local_registry(registry_path)

    assert entry.name == "local"
    assert entry.is_current is True
    assert entry.index_exists is True
    assert (registry_path / REGISTRY_INDEX_FILENAME).exists()
    config = load_registry_config()
    assert config.current_registry == "local"
    assert config.registries["local"] == str(registry_path.resolve())
    assert config_path() == tmp_path / "config" / "registries.json"


def test_add_and_use_existing_registry(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    first = init_local_registry(tmp_path / "first", name="first")
    second_path = tmp_path / "second"
    second_path.mkdir()

    added = add_registry("second", second_path)
    selected = use_registry("second")

    assert first.name == "first"
    assert added.name == "second"
    assert added.is_current is False
    assert selected.is_current is True
    entries = {entry.name: entry for entry in list_registries()}
    assert entries["first"].is_current is False
    assert entries["second"].is_current is True
