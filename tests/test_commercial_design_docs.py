from pathlib import Path


def test_commercial_agent_platform_doc_sets_future_only_boundaries() -> None:
    docs = Path("docs/commercial-agent-platform.md").read_text(encoding="utf-8")
    lower = docs.lower()

    assert "Before pip install, ask why." in docs
    assert "Stop AI agents from pip-installing mystery code." in docs
    assert "decision support, not proof" in docs
    assert "no hosted service" in lower
    assert "no billing provider is configured" in lower
    assert "no api keys are required" in lower
    assert "no secrets are stored" in lower
    assert "no cloud result is fabricated" in lower
    assert "no hosted decision is treated as definitive malware detection" in lower


def test_commercial_agent_platform_doc_covers_expected_roadmap_tiers() -> None:
    docs = Path("docs/commercial-agent-platform.md").read_text(encoding="utf-8")

    assert "Free local CLI" in docs
    assert "Pro local policy packs" in docs
    assert "Team review dashboard" in docs
    assert "Hosted package review cache" in docs
    assert "Agent install gateway" in docs
    assert "MCP And Agent Gateway Design" in docs
