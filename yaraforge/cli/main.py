"""
yaraforge.cli.main
~~~~~~~~~~~~~~~~~~
Command-line interface for YARAForge.

Commands:
  scan      Scan files, directories, or processes
  deploy    Deploy rules to local or remote targets
  sync      Pull rules from GitHub or remote sources
  compile   Compile rules to a fast .yarc bundle
  validate  Validate rule syntax without scanning
  report    Convert existing JSON results to another format
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

import click

from yaraforge.engine.loader import RuleLoader
from yaraforge.engine.scanner import Scanner, ScanSummary
from yaraforge.report.reporter import Reporter

# ── Logging setup ──────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


# ── CLI root ───────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="yaraforge")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """
    \b
    ██╗   ██╗ █████╗ ██████╗  █████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
    ╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
     ╚████╔╝ ███████║██████╔╝███████║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
      ╚██╔╝  ██╔══██║██╔══██╗██╔══██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
       ██║   ██║  ██║██║  ██║██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

    YARA rule deployment and scanning automation.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ── scan command ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("targets", nargs=-1, required=True, type=click.Path())
@click.option("--rules", "-r", "rule_paths", multiple=True, required=True,
              help="YARA rule file or directory (repeatable).")
@click.option("--recursive/--no-recursive", default=True, show_default=True,
              help="Recursively scan directories.")
@click.option("--threads", "-t", default=4, show_default=True,
              help="Number of scanner threads.")
@click.option("--max-size", default=50, show_default=True,
              help="Max file size to scan in MB.")
@click.option("--timeout", default=60, show_default=True,
              help="Per-file scan timeout in seconds.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write report to file.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "sarif", "html", "csv", "text"]),
              default="text", show_default=True,
              help="Output format.")
@click.option("--exclude-ext", multiple=True,
              help="File extensions to exclude (e.g. .jpg).")
@click.option("--pid", type=int, default=None,
              help="Scan a running process by PID.")
@click.option("--exit-code/--no-exit-code", default=True,
              help="Exit with code 1 if matches are found.")
@click.pass_context
def scan(
    ctx: click.Context,
    targets: tuple,
    rule_paths: tuple,
    recursive: bool,
    threads: int,
    max_size: int,
    timeout: int,
    output: Optional[str],
    fmt: str,
    exclude_ext: tuple,
    pid: Optional[int],
    exit_code: bool,
) -> None:
    """Scan files, directories, or processes for YARA matches."""
    loader = RuleLoader(strict=False)

    # Load rules
    for rp in rule_paths:
        p = Path(rp)
        if p.is_dir():
            loader.load_directory(p)
        elif p.is_file():
            loader.load_file(p)
        else:
            click.echo(f"[!] Rule path not found: {rp}", err=True)
            sys.exit(2)

    result = loader.compile()
    if not result.success:
        click.echo(f"[!] Rule compilation failed: {result.error}", err=True)
        sys.exit(2)

    click.echo(
        f"[*] Compiled {result.rule_count} rules in {result.compile_time_ms:.1f}ms",
        err=True,
    )

    scanner = Scanner(
        rules=result.rules,
        max_file_size=max_size * 1024 * 1024,
        timeout=timeout,
        threads=threads,
        exclude_extensions=set(exclude_ext) if exclude_ext else None,
    )

    all_results = []

    # Process scan
    if pid is not None:
        click.echo(f"[*] Scanning process PID {pid}...", err=True)
        all_results.append(scanner.scan_process(pid))

    # File/directory scan
    for target in targets:
        p = Path(target)
        if p.is_file():
            all_results.append(scanner.scan_file(p))
        elif p.is_dir():
            click.echo(f"[*] Scanning directory: {p}", err=True)
            summary = scanner.scan_directory(
                p,
                recursive=recursive,
                progress_callback=lambda r: (
                    click.echo(f"  [!] MATCH: {r.target} ({r.match_count} rules)", err=True)
                    if r.match_count > 0 else None
                ),
            )
            all_results.extend(summary.results)
        else:
            click.echo(f"[!] Target not found: {target}", err=True)

    # Build summary
    summary = ScanSummary(
        total_targets=len(all_results),
        results=all_results,
    )
    for r in all_results:
        if r.skipped:
            summary.skipped += 1
        elif r.error:
            summary.errors += 1
        else:
            summary.scanned += 1
            summary.total_bytes += r.file_size
            summary.matches += r.match_count
            if r.match_count == 0:
                summary.clean += 1

    reporter = Reporter(summary)

    # Output
    if output:
        path = reporter.save(output, fmt=fmt)
        click.echo(f"[*] Report saved to {path}", err=True)
    else:
        if fmt == "text":
            click.echo(reporter.to_text())
        elif fmt == "json":
            click.echo(reporter.to_json())
        elif fmt == "sarif":
            click.echo(reporter.to_sarif())
        elif fmt == "csv":
            click.echo(reporter.to_csv())
        elif fmt == "html":
            click.echo(reporter.to_html())

    if exit_code and summary.matches > 0:
        sys.exit(1)


# ── validate command ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.pass_context
def validate(ctx: click.Context, paths: tuple) -> None:
    """Validate YARA rule syntax without scanning."""
    loader = RuleLoader(strict=True)
    errors = 0
    total = 0

    for path_str in paths:
        p = Path(path_str)
        files = list(p.rglob("*.yar")) + list(p.rglob("*.yara")) if p.is_dir() else [p]
        for f in files:
            total += 1
            try:
                meta = loader.load_file(f)
                click.echo(f"  ✓ {f.name} ({meta.rule_count} rules)")
            except ValueError as exc:
                click.echo(f"  ✗ {f.name}: {exc}", err=True)
                errors += 1

    click.echo(f"\n{total - errors}/{total} files valid.")
    if errors:
        sys.exit(1)


# ── compile command ────────────────────────────────────────────────────────────

@cli.command()
@click.argument("rule_dirs", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--output", "-o", required=True, type=click.Path(),
              help="Output path for compiled .yarc bundle.")
@click.pass_context
def compile(ctx: click.Context, rule_dirs: tuple, output: str) -> None:
    """Compile YARA rules into a fast .yarc bundle."""
    loader = RuleLoader()
    for d in rule_dirs:
        p = Path(d)
        if p.is_dir():
            loader.load_directory(p)
        else:
            loader.load_file(p)

    result = loader.compile()
    if not result.success:
        click.echo(f"[!] Compilation failed: {result.error}", err=True)
        sys.exit(1)

    out = loader.save_compiled(output)
    click.echo(
        f"[✓] Compiled {result.rule_count} rules → {out} "
        f"({out.stat().st_size / 1024:.1f} KB, {result.compile_time_ms:.1f}ms)"
    )


# ── sync command ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("repo")
@click.option("--branch", default="main", show_default=True)
@click.option("--dest", "-d", required=True, type=click.Path(),
              help="Local directory to sync rules into.")
@click.option("--subpath", default="", help="Sub-directory within the repo.")
@click.pass_context
def sync(ctx: click.Context, repo: str, branch: str, dest: str, subpath: str) -> None:
    """Sync YARA rules from a GitHub repository."""
    from yaraforge.deploy.deployer import RuleDeployer
    deployer = RuleDeployer()
    click.echo(f"[*] Syncing from github.com/{repo} ({branch})...")
    count = deployer.sync_from_github(repo, branch=branch, dest_dir=dest, subpath=subpath)
    click.echo(f"[✓] Synced {count} rule files to {dest}")


# ── deploy command ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("source_dir", type=click.Path(exists=True))
@click.option("--target-type", type=click.Choice(["local", "ssh"]),
              default="local", show_default=True)
@click.option("--target-path", required=True, help="Destination path or remote path.")
@click.option("--host", default=None, help="SSH host (for ssh target type).")
@click.option("--user", default=None, help="SSH user.")
@click.option("--port", default=22, show_default=True, help="SSH port.")
@click.option("--key-file", default=None, help="SSH private key file.")
@click.option("--dry-run", is_flag=True, help="Simulate deployment without writing files.")
@click.pass_context
def deploy(
    ctx: click.Context,
    source_dir: str,
    target_type: str,
    target_path: str,
    host: Optional[str],
    user: Optional[str],
    port: int,
    key_file: Optional[str],
    dry_run: bool,
) -> None:
    """Deploy YARA rules to a local path or remote SSH host."""
    from yaraforge.deploy.deployer import RuleDeployer, DeployTarget

    target = DeployTarget(
        name=host or target_path,
        type=target_type,
        path=target_path,
        host=host,
        user=user,
        port=port,
        key_file=key_file,
    )

    deployer = RuleDeployer()
    prefix = "[DRY RUN] " if dry_run else ""
    click.echo(f"{prefix}[*] Deploying from {source_dir} → {target.name}...")
    record = deployer.deploy(source_dir, target, dry_run=dry_run)

    if record.success:
        click.echo(
            f"[✓] Deployed {record.rule_count} rules "
            f"({record.files_deployed} files) in {record.duration_seconds:.2f}s"
        )
    else:
        click.echo(f"[!] Deployment failed: {record.error}", err=True)
        sys.exit(1)


# ── report command ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("json_report", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt",
              type=click.Choice(["sarif", "html", "csv", "text"]),
              required=True, help="Output format.")
@click.option("--output", "-o", type=click.Path(), required=True,
              help="Output file path.")
def report(json_report: str, fmt: str, output: str) -> None:
    """Convert an existing JSON scan report to another format."""
    import dataclasses
    from yaraforge.engine.scanner import ScanResult, RuleMatch, StringMatch

    data = json.loads(Path(json_report).read_text())
    results = []
    for r in data.get("results", []):
        matches = []
        for m in r.get("matches", []):
            strings = [
                StringMatch(
                    identifier=s["identifier"],
                    offset=s["offset"],
                    data=bytes.fromhex(s.get("data", "")),
                )
                for s in m.get("strings", [])
            ]
            matches.append(RuleMatch(
                rule=m["rule"],
                namespace=m["namespace"],
                tags=m["tags"],
                meta=m["meta"],
                strings=strings,
            ))
        results.append(ScanResult(
            target=r["target"],
            target_type=r["target_type"],
            matches=matches,
            error=r.get("error"),
            scan_time_ms=r.get("scan_time_ms", 0),
            file_size=r.get("file_size", 0),
            sha256=r.get("sha256"),
            skipped=r.get("skipped", False),
            skip_reason=r.get("skip_reason"),
        ))

    summary = ScanSummary(
        total_targets=data.get("total_targets", len(results)),
        scanned=data.get("scanned", 0),
        skipped=data.get("skipped", 0),
        errors=data.get("errors", 0),
        matches=data.get("matches", 0),
        clean=data.get("clean", 0),
        total_bytes=data.get("total_bytes", 0),
        elapsed_seconds=data.get("elapsed_seconds", 0),
        results=results,
    )

    reporter = Reporter(summary)
    path = reporter.save(output, fmt=fmt)
    click.echo(f"[✓] Report saved to {path}")


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
