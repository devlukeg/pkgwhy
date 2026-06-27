import json

from pkgwhy.core.models import Confidence, RuleCategory, RuleSeverity
from pkgwhy.risk.rules import (
    RULE_CATALOG_SCHEMA_VERSION,
    RULES,
    make_rule_evidence,
    rule_catalog_snapshot,
    rule_ids,
    rules_by_category,
)

EXPECTED_RULE_IDS = (
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
    "PKGWHY-PY-009",
    "PKGWHY-BUILD-001",
    "PKGWHY-BUILD-002",
    "PKGWHY-BUILD-003",
    "PKGWHY-BUILD-004",
    "PKGWHY-BUILD-005",
    "PKGWHY-BUILD-006",
    "PKGWHY-NET-001",
    "PKGWHY-CRED-001",
    "PKGWHY-JS-001",
    "PKGWHY-JS-002",
    "PKGWHY-JS-003",
    "PKGWHY-JS-004",
    "PKGWHY-JS-005",
    "PKGWHY-BIN-001",
    "PKGWHY-BIN-002",
    "PKGWHY-BIN-003",
)


def test_rule_catalog_defines_current_rule_metadata() -> None:
    assert set(EXPECTED_RULE_IDS) == set(RULES)
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


def test_rule_catalog_order_and_ids_are_stable() -> None:
    assert rule_ids() == EXPECTED_RULE_IDS
    assert len(rule_ids()) == len(set(rule_ids()))
    assert all(rule.rule_id == rule_id for rule_id, rule in zip(rule_ids(), RULES.values(), strict=True))


def test_rule_catalog_snapshot_is_json_friendly_and_versioned() -> None:
    snapshot = rule_catalog_snapshot()

    json.dumps(snapshot)
    assert snapshot["schema_version"] == RULE_CATALOG_SCHEMA_VERSION
    assert snapshot["rule_count"] == len(EXPECTED_RULE_IDS)
    rules = snapshot["rules"]
    assert isinstance(rules, list)
    assert [item["rule_id"] for item in rules] == list(EXPECTED_RULE_IDS)
    assert all(isinstance(item["default_message"], str) for item in rules)
    assert all(isinstance(item["category"], str) for item in rules)
    assert all(isinstance(item["severity"], str) for item in rules)
    assert all(isinstance(item["confidence"], str) for item in rules)


def test_rules_by_category_preserves_rule_definitions() -> None:
    grouped = rules_by_category()
    expected_by_category: dict[RuleCategory, list[str]] = {}
    for rule_id in EXPECTED_RULE_IDS:
        expected_by_category.setdefault(RULES[rule_id].category, []).append(rule_id)

    assert len(grouped[RuleCategory.STATIC_ANALYSIS]) >= 1
    assert RULES["PKGWHY-VULN-001"] in grouped[RuleCategory.VULNERABILITY]
    assert RULES["PKGWHY-BIN-001"] in grouped[RuleCategory.BINARY]
    assert sum(len(items) for items in grouped.values()) == len(RULES)
    assert {
        category: tuple(rule.rule_id for rule in definitions)
        for category, definitions in grouped.items()
    } == {
        category: tuple(rule_ids)
        for category, rule_ids in expected_by_category.items()
    }
