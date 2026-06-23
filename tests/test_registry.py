import sys
from pathlib import Path

import pytest

from pkgwhy.registry.local import (
    REGISTRY_INDEX_FILENAME,
    add_registry,
    config_path,
    init_local_registry,
    list_registries,
    load_registry_config,
    save_registry_config,
    use_registry,
)


def test_init_local_registry_creates_index_and_selects_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_add_and_use_existing_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_add_registry_rejects_duplicate_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKGWHY_CONFIG_HOME", str(tmp_path / "config"))
    init_local_registry(tmp_path / "first", name="local")
    second_path = tmp_path / "second"
    second_path.mkdir()

    with pytest.raises(ValueError, match="already exists"):
        add_registry("local", second_path)


def test_load_registry_config_ignores_invalid_config(tmp_path: Path) -> None:
    config_file = tmp_path / "registries.json"
    config_file.write_text('{"registries": []}', encoding="utf-8")

    config = load_registry_config(config_file)

    assert config.registries == {}


def test_save_registry_config_uses_final_path(tmp_path: Path) -> None:
    config_file = tmp_path / "registries.json"
    config = load_registry_config(config_file)

    save_registry_config(config, config_file)

    assert config_file.exists()
    assert not (tmp_path / ".registries.json.tmp").exists()


@pytest.mark.skipif(
    sys.platform in {"win32", "darwin"},
    reason="XDG_CONFIG_HOME is only used on Unix-like platforms",
)
def test_empty_xdg_config_home_uses_default_config_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PKGWHY_CONFIG_HOME", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", "")

    assert config_path() == Path.home() / ".config" / "pkgwhy" / "registries.json"
