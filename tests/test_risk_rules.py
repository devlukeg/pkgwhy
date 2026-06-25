from pkgwhy.core.models import Confidence, RuleCategory, RuleSeverity
from pkgwhy.risk.rules import RULES, make_rule_evidence


def test_rule_catalog_defines_current_rule_metadata() -> None:
    required_rules = {
        "PKGWHY-VULN-001",
        "PKGWHY-RISK-001",
        "PKGWHY-RISK-002",
        "PKGWHY-RISK-003",
        "PKGWHY-RISK-004",
        "PKGWHY-RISK-005",
        "PKGWHY-RISK-006",
        "PKGWHY-PY-001",
        "PKGWHY-PY-002",
        "PKGWHY-PY-003",
        "PKGWHY-PY-004",
        "PKGWHY-PY-005",
        "PKGWHY-PY-006",
        "PKGWHY-PY-007",
        "PKGWHY-PY-008",
    }

    assert required_rules <= set(RULES)
    assert RULES["PKGWHY-VULN-001"].category == RuleCategory.VULNERABILITY
    assert RULES["PKGWHY-RISK-005"].category == RuleCategory.STATIC_ANALYSIS
    assert all(rule.false_positive_note for rule in RULES.values())


def test_make_rule_evidence_preserves_optional_location_fields() -> None:
    evidence = make_rule_evidence(
        "PKGWHY-RISK-005",
        message="Static capability signal detected: eval.",
        evidence=["example.py:3 references eval"],
        severity=RuleSeverity.HIGH,
        confidence=Confidence.HIGH,
        file_path="example.py",
        line_number=3,
        symbol="eval",
    )

    assert evidence.rule_id == "PKGWHY-RISK-005"
    assert evidence.name == "static_capability_signal"
    assert evidence.category == RuleCategory.STATIC_ANALYSIS
    assert evidence.severity == RuleSeverity.HIGH
    assert evidence.confidence == Confidence.HIGH
    assert evidence.file_path == "example.py"
    assert evidence.line_number == 3
    assert evidence.symbol == "eval"
    assert "not proof" in (evidence.false_positive_note or "")
