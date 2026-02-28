"""
yaraforge.report.reporter
~~~~~~~~~~~~~~~~~~~~~~~~~
Reporting engine for YARA scan results.

Supported output formats:
- JSON (machine-readable, full detail)
- SARIF 2.1.0 (GitHub Code Scanning compatible)
- HTML (human-readable, self-contained)
- CSV (spreadsheet-friendly summary)
- Plain text (console summary)
"""

from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from yaraforge.engine.scanner import ScanSummary, ScanResult


class Reporter:
    """Generates scan reports in multiple formats."""

    TOOL_NAME = "yaraforge"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://github.com/rawqubit/yaraforge"

    def __init__(self, summary: ScanSummary):
        self.summary = summary

    # ------------------------------------------------------------------
    # Public format methods
    # ------------------------------------------------------------------

    def to_json(self, pretty: bool = True) -> str:
        """Serialize the full scan summary to JSON."""
        return json.dumps(self.summary.to_dict(), indent=2 if pretty else None)

    def to_sarif(self) -> str:
        """
        Generate a SARIF 2.1.0 report compatible with GitHub Code Scanning.
        https://docs.oasis-open.org/sarif/sarif/v2.1.0/
        """
        rules = {}
        results = []

        for scan_result in self.summary.results:
            for match in scan_result.matches:
                rule_id = f"{match.namespace}/{match.rule}"

                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": match.rule,
                        "shortDescription": {
                            "text": match.meta.get("description", f"YARA rule: {match.rule}")
                        },
                        "fullDescription": {
                            "text": match.meta.get("description", f"YARA rule match: {match.rule}")
                        },
                        "properties": {
                            "tags": match.tags,
                            "severity": match.meta.get("severity", "warning"),
                        },
                    }

                artifact_location = {"uri": scan_result.target}
                locations = []
                for s in match.strings:
                    locations.append({
                        "physicalLocation": {
                            "artifactLocation": artifact_location,
                            "region": {"byteOffset": s.offset},
                        }
                    })

                results.append({
                    "ruleId": rule_id,
                    "level": self._severity_to_sarif(match.meta.get("severity", "warning")),
                    "message": {
                        "text": (
                            f"YARA rule '{match.rule}' matched in {scan_result.target}. "
                            f"Tags: {', '.join(match.tags) or 'none'}. "
                            f"Strings matched: {len(match.strings)}."
                        )
                    },
                    "locations": locations or [{"physicalLocation": {"artifactLocation": artifact_location}}],
                })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.TOOL_NAME,
                        "version": self.TOOL_VERSION,
                        "informationUri": self.TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                }],
            }],
        }
        return json.dumps(sarif, indent=2)

    def to_html(self) -> str:
        """Generate a self-contained HTML report."""
        s = self.summary
        matched = s.matched_targets
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = ""
        for r in s.results:
            if r.match_count > 0:
                for match in r.matches:
                    rows += f"""
                    <tr class="match">
                        <td>{r.target}</td>
                        <td><span class="badge rule">{match.rule}</span></td>
                        <td>{', '.join(match.tags) or '—'}</td>
                        <td>{match.meta.get('severity', '—')}</td>
                        <td>{len(match.strings)}</td>
                        <td>{r.sha256[:12] + '...' if r.sha256 else '—'}</td>
                    </tr>"""
            elif r.error:
                rows += f"""
                    <tr class="error">
                        <td>{r.target}</td>
                        <td colspan="5"><em>Error: {r.error}</em></td>
                    </tr>"""

        throughput = (
            f"{(s.total_bytes / 1024 / 1024) / s.elapsed_seconds:.1f} MB/s"
            if s.elapsed_seconds > 0 else "—"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>YARAForge Scan Report — {timestamp}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }}
  h1 {{ color: #58a6ff; }} h2 {{ color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 24px 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 120px; text-align: center; }}
  .stat .value {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; }}
  .danger .value {{ color: #f85149; }} .success .value {{ color: #3fb950; }} .warn .value {{ color: #d29922; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 12px; text-align: left; color: #8b949e; font-size: 0.85em; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 0.9em; word-break: break-all; }}
  tr.match:hover {{ background: #1c2128; }}
  tr.error td {{ color: #f85149; }}
  .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }}
  .badge.rule {{ background: #1f3a5f; color: #58a6ff; }}
  footer {{ margin-top: 32px; color: #484f58; font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<h1>🛡️ YARAForge Scan Report</h1>
<p style="color:#8b949e">Generated: {timestamp} &nbsp;|&nbsp; Duration: {s.elapsed_seconds:.2f}s &nbsp;|&nbsp; Throughput: {throughput}</p>

<div class="stats">
  <div class="stat"><div class="value">{s.total_targets}</div><div class="label">Total Targets</div></div>
  <div class="stat"><div class="value">{s.scanned}</div><div class="label">Scanned</div></div>
  <div class="stat {'danger' if s.matches > 0 else 'success'}"><div class="value">{s.matches}</div><div class="label">Matches</div></div>
  <div class="stat success"><div class="value">{s.clean}</div><div class="label">Clean</div></div>
  <div class="stat warn"><div class="value">{s.skipped}</div><div class="label">Skipped</div></div>
  <div class="stat {'danger' if s.errors > 0 else ''}"><div class="value">{s.errors}</div><div class="label">Errors</div></div>
</div>

<h2>Matches ({len(matched)} files)</h2>
<table>
  <thead><tr><th>File</th><th>Rule</th><th>Tags</th><th>Severity</th><th>Strings</th><th>SHA-256</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="6" style="text-align:center;color:#3fb950">✓ No matches found — all targets clean</td></tr>'}</tbody>
</table>

<footer>YARAForge &nbsp;|&nbsp; github.com/rawqubit/yaraforge</footer>
</body>
</html>"""

    def to_csv(self) -> str:
        """Generate a CSV summary of all scan results."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "target", "target_type", "sha256", "file_size_bytes",
            "scan_time_ms", "match_count", "matched_rules",
            "error", "skipped", "skip_reason",
        ])
        for r in self.summary.results:
            writer.writerow([
                r.target,
                r.target_type,
                r.sha256 or "",
                r.file_size,
                f"{r.scan_time_ms:.2f}",
                r.match_count,
                "|".join(m.rule for m in r.matches),
                r.error or "",
                r.skipped,
                r.skip_reason or "",
            ])
        return output.getvalue()

    def to_text(self) -> str:
        """Generate a plain-text console summary."""
        s = self.summary
        lines = [
            "=" * 60,
            "  YARAForge Scan Summary",
            "=" * 60,
            f"  Targets:   {s.total_targets}",
            f"  Scanned:   {s.scanned}",
            f"  Matches:   {s.matches}",
            f"  Clean:     {s.clean}",
            f"  Skipped:   {s.skipped}",
            f"  Errors:    {s.errors}",
            f"  Duration:  {s.elapsed_seconds:.2f}s",
            f"  Data:      {s.total_bytes / 1024 / 1024:.1f} MB",
            "=" * 60,
        ]
        if s.matched_targets:
            lines.append("\n  MATCHES:")
            for r in s.matched_targets:
                lines.append(f"\n  [!] {r.target}")
                for m in r.matches:
                    lines.append(f"      Rule:      {m.rule}")
                    lines.append(f"      Namespace: {m.namespace}")
                    lines.append(f"      Tags:      {', '.join(m.tags) or 'none'}")
                    lines.append(f"      Strings:   {len(m.strings)} matched")
        else:
            lines.append("\n  [✓] No matches found — all targets clean.")
        lines.append("")
        return "\n".join(lines)

    def save(self, output_path: str | Path, fmt: str = "json") -> Path:
        """Save the report to a file in the specified format."""
        output_path = Path(output_path)
        formatters = {
            "json": self.to_json,
            "sarif": self.to_sarif,
            "html": self.to_html,
            "csv": self.to_csv,
            "text": self.to_text,
        }
        if fmt not in formatters:
            raise ValueError(f"Unknown format '{fmt}'. Choose from: {list(formatters)}")
        output_path.write_text(formatters[fmt](), encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_sarif(severity: str) -> str:
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")
