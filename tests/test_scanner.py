"""Tests for yaraforge.engine.scanner"""

import tempfile
from pathlib import Path

import pytest
import yara

from yaraforge.engine.scanner import Scanner, ScanResult, ScanSummary


RULE_SOURCE = """
rule DetectHello
{
    meta:
        description = "Detects hello world string"
        severity = "low"
    strings:
        $hello = "hello world"
    condition:
        $hello
}
"""


def make_scanner(rule_source: str = RULE_SOURCE, **kwargs) -> Scanner:
    rules = yara.compile(source=rule_source)
    return Scanner(rules=rules, **kwargs)


class TestScanner:

    def test_scan_file_match(self, tmp_path):
        target = tmp_path / "test.txt"
        target.write_bytes(b"hello world this is a test")
        scanner = make_scanner()
        result = scanner.scan_file(target)
        assert not result.error
        assert result.match_count == 1
        assert result.matches[0].rule == "DetectHello"
        assert result.sha256 is not None
        assert result.file_size == len(b"hello world this is a test")

    def test_scan_file_no_match(self, tmp_path):
        target = tmp_path / "clean.txt"
        target.write_bytes(b"nothing suspicious here")
        scanner = make_scanner()
        result = scanner.scan_file(target)
        assert result.is_clean
        assert result.match_count == 0

    def test_scan_file_not_found(self):
        scanner = make_scanner()
        result = scanner.scan_file("/nonexistent/file.txt")
        assert result.error == "File not found"

    def test_scan_file_excluded_extension(self, tmp_path):
        target = tmp_path / "image.jpg"
        target.write_bytes(b"hello world")
        scanner = make_scanner()
        result = scanner.scan_file(target)
        assert result.skipped
        assert "Excluded extension" in result.skip_reason

    def test_scan_file_too_large(self, tmp_path):
        target = tmp_path / "big.bin"
        target.write_bytes(b"hello world " * 1000)
        scanner = make_scanner(max_file_size=100)  # 100 bytes limit
        result = scanner.scan_file(target)
        assert result.skipped
        assert "too large" in result.skip_reason

    def test_scan_bytes_match(self):
        scanner = make_scanner()
        result = scanner.scan_bytes(b"hello world payload", label="test_payload")
        assert result.match_count == 1
        assert result.target == "test_payload"
        assert result.target_type == "memory"

    def test_scan_bytes_no_match(self):
        scanner = make_scanner()
        result = scanner.scan_bytes(b"nothing here", label="clean_payload")
        assert result.is_clean

    def test_scan_directory(self, tmp_path):
        (tmp_path / "match.txt").write_bytes(b"hello world")
        (tmp_path / "clean.txt").write_bytes(b"nothing here")
        (tmp_path / "skip.jpg").write_bytes(b"hello world")  # excluded
        scanner = make_scanner()
        summary = scanner.scan_directory(tmp_path, recursive=False)
        assert isinstance(summary, ScanSummary)
        assert summary.total_targets == 3
        assert summary.matches >= 1
        assert summary.skipped >= 1

    def test_scan_directory_recursive(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "deep.txt").write_bytes(b"hello world")
        scanner = make_scanner()
        summary = scanner.scan_directory(tmp_path, recursive=True)
        assert summary.matches >= 1

    def test_scan_directory_progress_callback(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"hello world")
        scanner = make_scanner()
        seen = []
        scanner.scan_directory(tmp_path, progress_callback=lambda r: seen.append(r))
        assert len(seen) >= 1

    def test_stream_results(self, tmp_path):
        for i in range(3):
            (tmp_path / f"f{i}.txt").write_bytes(b"hello world")
        scanner = make_scanner()
        results = list(scanner.stream_results(tmp_path))
        assert len(results) == 3

    def test_scan_result_to_dict(self, tmp_path):
        target = tmp_path / "test.txt"
        target.write_bytes(b"hello world")
        scanner = make_scanner()
        result = scanner.scan_file(target)
        d = result.to_dict()
        assert "target" in d
        assert "matches" in d
        assert "sha256" in d
        assert "scan_time_ms" in d

    def test_summary_to_dict(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"hello world")
        scanner = make_scanner()
        summary = scanner.scan_directory(tmp_path)
        d = summary.to_dict()
        assert "total_targets" in d
        assert "throughput_mb_s" in d
        assert "results" in d
