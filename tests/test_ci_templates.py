from pathlib import Path


def test_github_action_package_gate_template_is_local_and_secret_free() -> None:
    template = Path("examples/github-actions/pkgwhy-package-gate.yml").read_text(encoding="utf-8")
    lower = template.lower()

    assert "PKGWHY_MODE: advisory" in template
    assert "python -m pip install pkgwhy" in template
    assert "python -m pkgwhy precheck -r requirements.txt --json --enforce-exit-code" in template
    assert "python -m pkgwhy audit --limit 50 --json" in template
    assert "python -m pkgwhy audit --limit 50 --markdown" in template
    assert "python -m pkgwhy agent precheck" in template
    assert "actions/upload-artifact" in template
    assert "secrets." not in lower
    assert "api_key" not in lower
    assert "stripe" not in lower
    assert "billing" not in lower


def test_ci_template_docs_describe_modes_and_boundaries() -> None:
    docs = Path("docs/ci-templates.md").read_text(encoding="utf-8")

    assert "advisory" in docs
    assert "strict" in docs
    assert "agent" in docs
    assert "No secrets are required" in docs
    assert "No hosted `pkgwhy` service is contacted" in docs
    assert "not proof of malicious or safe behavior" in docs
