"""Unit tests for rule definitions registry."""

from qv.rules.registry import RULES_CATALOG, get_rule_definition


def test_rule_definitions_exist():
    assert "DEP-001" in RULES_CATALOG
    assert "DEP-002" in RULES_CATALOG
    assert "DEP-003" in RULES_CATALOG
    assert "ENV-001" in RULES_CATALOG
    assert "IMP-001" in RULES_CATALOG
    assert "PKG-001" in RULES_CATALOG


def test_get_rule_definition_case_insensitive():
    rule = get_rule_definition("dep-001")
    assert rule is not None
    assert rule.id == "DEP-001"
    assert rule.category == "dependency"
