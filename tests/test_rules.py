"""Unit tests for rule definitions registry."""

from qv.rules.registry import RULES_CATALOG, get_rule_definition


def test_rule_definitions_exist():
    assert "DEP-001" in RULES_CATALOG
    assert "DEP-002" in RULES_CATALOG
    assert "DEP-003" in RULES_CATALOG
    assert "DEP-007" in RULES_CATALOG
    assert "ENV-001" in RULES_CATALOG
    assert "IMP-001" in RULES_CATALOG
    assert "PKG-001" in RULES_CATALOG


def test_get_rule_definition_case_insensitive():
    rule = get_rule_definition("dep-001")
    assert rule is not None
    assert rule.id == "DEP-001"
    assert rule.category == "dependency"


def test_dep_003_rule_definition():
    rule = get_rule_definition("DEP-003")
    assert rule is not None
    assert rule.title == "No direct import detected"
    assert "no direct imports were detected" in rule.description


def test_dep_007_rule_definition():
    rule = get_rule_definition("DEP-007")
    assert rule is not None
    assert rule.title == "Undeclared transitive dependency"
    assert "transitive" in rule.description.lower()
    assert rule.default_severity.value == "warning"
