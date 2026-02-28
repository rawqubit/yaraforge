"""Tests for yaraforge.engine.loader"""

import hashlib
import tempfile
from pathlib import Path

import pytest
import yara

from yaraforge.engine.loader import RuleLoader, RuleMetadata


VALID_RULE = """
rule TestRule : test_tag
{
    meta:
        description = "Test rule"
        severity = "low"
    strings:
        $test = "hello world"
    condition:
        $test
}
"""

INVALID_RULE = """
rule BrokenRule {
    strings:
        $x = "test"
    condition:
        $undefined_var
"""

MULTI_RULE = """
rule RuleOne { strings: $a = "foo" condition: $a }
rule RuleTwo { strings: $b = "bar" condition: $b }
rule RuleThree { strings: $c = "baz" condition: $c }
"""


class TestRuleLoader:

    def test_load_valid_file(self, tmp_path):
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(VALID_RULE)
        loader = RuleLoader()
        meta = loader.load_file(rule_file)
        assert isinstance(meta, RuleMetadata)
        assert meta.rule_count == 1
        assert "test_tag" in meta.tags
        assert meta.sha256 == hashlib.sha256(VALID_RULE.encode()).hexdigest()

    def test_load_invalid_file_raises(self, tmp_path):
        rule_file = tmp_path / "bad.yar"
        rule_file.write_text(INVALID_RULE)
        loader = RuleLoader()
        with pytest.raises(ValueError, match="YARA syntax error"):
            loader.load_file(rule_file)

    def test_load_nonexistent_file_raises(self):
        loader = RuleLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_file("/nonexistent/path/rule.yar")

    def test_load_wrong_extension_raises(self, tmp_path):
        f = tmp_path / "rule.txt"
        f.write_text(VALID_RULE)
        loader = RuleLoader()
        with pytest.raises(ValueError, match="Unsupported extension"):
            loader.load_file(f)

    def test_load_directory(self, tmp_path):
        for i in range(3):
            (tmp_path / f"rule{i}.yar").write_text(
                f'rule Rule{i} {{ strings: $s = "test{i}" condition: $s }}'
            )
        loader = RuleLoader()
        results = loader.load_directory(tmp_path)
        assert len(results) == 3
        assert all(isinstance(r, RuleMetadata) for r in results)

    def test_count_rules_multi(self, tmp_path):
        rule_file = tmp_path / "multi.yar"
        rule_file.write_text(MULTI_RULE)
        loader = RuleLoader()
        meta = loader.load_file(rule_file)
        assert meta.rule_count == 3

    def test_compile_success(self, tmp_path):
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(VALID_RULE)
        loader = RuleLoader()
        loader.load_file(rule_file)
        result = loader.compile()
        assert result.success
        assert result.rules is not None
        assert result.rule_count == 1
        assert result.compile_time_ms > 0

    def test_compile_empty_returns_error(self):
        loader = RuleLoader()
        result = loader.compile()
        assert not result.success
        assert "No rules loaded" in result.error

    def test_save_and_load_compiled(self, tmp_path):
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(VALID_RULE)
        loader = RuleLoader()
        loader.load_file(rule_file)
        loader.compile()
        bundle = tmp_path / "rules.yarc"
        loader.save_compiled(bundle)
        assert bundle.exists()

        loader2 = RuleLoader()
        rules = loader2.load_compiled(bundle)
        assert rules is not None

    def test_list_loaded(self, tmp_path):
        for i in range(2):
            (tmp_path / f"r{i}.yar").write_text(
                f'rule R{i} {{ strings: $s = "x{i}" condition: $s }}'
            )
        loader = RuleLoader()
        loader.load_directory(tmp_path)
        loaded = loader.list_loaded()
        assert len(loaded) == 2

    def test_export_manifest(self, tmp_path):
        import json
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(VALID_RULE)
        loader = RuleLoader()
        loader.load_file(rule_file)
        manifest_path = tmp_path / "manifest.json"
        loader.export_manifest(manifest_path)
        data = json.loads(manifest_path.read_text())
        assert data["rule_count"] == 1
        assert len(data["rules"]) == 1
