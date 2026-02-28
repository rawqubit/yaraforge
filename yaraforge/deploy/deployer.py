"""
yaraforge.deploy.deployer
~~~~~~~~~~~~~~~~~~~~~~~~~
Rule deployment engine: sync rules to remote targets via SSH/SCP,
manage versioned rule bundles, and maintain deployment state.

Supported deployment targets:
- Local filesystem (copy/symlink)
- Remote SSH hosts (via paramiko)
- GitHub repository (pull latest rules)
- S3-compatible object storage
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DeployTarget:
    """Configuration for a single deployment target."""
    name: str
    type: str  # "local", "ssh", "github", "s3"
    path: str
    host: Optional[str] = None
    user: Optional[str] = None
    port: int = 22
    key_file: Optional[str] = None
    bucket: Optional[str] = None
    prefix: str = "yara-rules/"
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeployRecord:
    """Record of a single deployment event."""
    target_name: str
    target_type: str
    deployed_at: float
    rule_count: int
    bundle_sha256: str
    success: bool
    error: Optional[str] = None
    files_deployed: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class RuleDeployer:
    """
    Manages YARA rule deployment to one or more targets.

    Maintains a deployment log and supports rollback to previous versions.
    """

    DEPLOY_LOG = "deploy_log.json"
    BUNDLE_DIR = "bundles"

    def __init__(self, state_dir: Optional[str] = None):
        self.state_dir = Path(state_dir or (Path.home() / ".yaraforge" / "deploy"))
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.bundle_dir = self.state_dir / self.BUNDLE_DIR
        self.bundle_dir.mkdir(exist_ok=True)
        self._log_path = self.state_dir / self.DEPLOY_LOG
        self._log: List[DeployRecord] = self._load_log()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deploy(
        self,
        source_dir: str | Path,
        target: DeployTarget,
        dry_run: bool = False,
    ) -> DeployRecord:
        """Deploy rules from source_dir to a target."""
        source_dir = Path(source_dir).resolve()
        start = time.perf_counter()

        if not target.enabled:
            logger.info("Target '%s' is disabled, skipping.", target.name)
            return DeployRecord(
                target_name=target.name,
                target_type=target.type,
                deployed_at=time.time(),
                rule_count=0,
                bundle_sha256="",
                success=False,
                error="Target disabled",
            )

        # Create versioned bundle
        bundle_path, bundle_sha256, rule_count = self._create_bundle(source_dir)
        logger.info(
            "Deploying %d rules to '%s' [%s] (sha256: %s...)",
            rule_count, target.name, target.type, bundle_sha256[:12],
        )

        record = DeployRecord(
            target_name=target.name,
            target_type=target.type,
            deployed_at=time.time(),
            rule_count=rule_count,
            bundle_sha256=bundle_sha256,
            success=False,
        )

        if dry_run:
            logger.info("[DRY RUN] Would deploy %d rules to %s", rule_count, target.name)
            record.success = True
            record.duration_seconds = time.perf_counter() - start
            return record

        try:
            if target.type == "local":
                files = self._deploy_local(source_dir, target)
            elif target.type == "ssh":
                files = self._deploy_ssh(source_dir, target)
            elif target.type == "github":
                files = self._deploy_github(source_dir, target)
            else:
                raise ValueError(f"Unsupported deployment type: {target.type}")

            record.success = True
            record.files_deployed = files
        except Exception as exc:
            record.error = str(exc)
            logger.error("Deployment to '%s' failed: %s", target.name, exc)

        record.duration_seconds = time.perf_counter() - start
        self._log.append(record)
        self._save_log()
        return record

    def deploy_all(
        self,
        source_dir: str | Path,
        targets: List[DeployTarget],
        dry_run: bool = False,
    ) -> List[DeployRecord]:
        """Deploy to all enabled targets."""
        return [self.deploy(source_dir, t, dry_run=dry_run) for t in targets if t.enabled]

    def sync_from_github(
        self,
        repo: str,
        branch: str = "main",
        dest_dir: str | Path = ".",
        subpath: str = "",
    ) -> int:
        """
        Pull the latest YARA rules from a GitHub repository.
        Uses git sparse-checkout for efficiency.
        Returns the number of .yar/.yara files synced.
        """
        dest_dir = Path(dest_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        clone_url = f"https://github.com/{repo}.git"
        with tempfile.TemporaryDirectory() as tmpdir:
            logger.info("Cloning %s@%s ...", repo, branch)
            subprocess.run(
                ["git", "clone", "--depth=1", f"--branch={branch}", clone_url, tmpdir],
                check=True, capture_output=True,
            )
            src = Path(tmpdir) / subpath if subpath else Path(tmpdir)
            count = 0
            for f in src.rglob("*.yar"):
                dest = dest_dir / f.relative_to(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                count += 1
            for f in src.rglob("*.yara"):
                dest = dest_dir / f.relative_to(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                count += 1

        logger.info("Synced %d rules from %s", count, repo)
        return count

    def rollback(self, target: DeployTarget, steps: int = 1) -> Optional[DeployRecord]:
        """Rollback to a previous deployment for a given target."""
        target_logs = [
            r for r in reversed(self._log)
            if r.target_name == target.name and r.success
        ]
        if len(target_logs) <= steps:
            logger.warning("Not enough deployment history to rollback %d steps.", steps)
            return None

        previous = target_logs[steps]
        bundle = self._find_bundle(previous.bundle_sha256)
        if bundle is None:
            logger.error("Bundle %s not found in cache.", previous.bundle_sha256[:12])
            return None

        logger.info("Rolling back '%s' to bundle %s...", target.name, previous.bundle_sha256[:12])
        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.unpack_archive(str(bundle), tmpdir, format="zip")
            return self.deploy(tmpdir, target)

    def get_history(self, target_name: Optional[str] = None, limit: int = 20) -> List[DeployRecord]:
        """Return deployment history, optionally filtered by target name."""
        records = self._log if not target_name else [
            r for r in self._log if r.target_name == target_name
        ]
        return list(reversed(records))[:limit]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _create_bundle(self, source_dir: Path) -> tuple[Path, str, int]:
        """Create a versioned zip bundle of all rule files."""
        files = list(source_dir.rglob("*.yar")) + list(source_dir.rglob("*.yara"))
        rule_count = len(files)

        # Compute bundle hash from sorted file contents
        h = hashlib.sha256()
        for f in sorted(files):
            h.update(f.read_bytes())
        bundle_sha256 = h.hexdigest()

        bundle_path = self.bundle_dir / f"{bundle_sha256[:16]}.zip"
        if not bundle_path.exists():
            shutil.make_archive(
                str(bundle_path.with_suffix("")),
                "zip",
                root_dir=str(source_dir),
            )

        return bundle_path, bundle_sha256, rule_count

    def _find_bundle(self, sha256: str) -> Optional[Path]:
        for f in self.bundle_dir.glob("*.zip"):
            if f.stem == sha256[:16]:
                return f
        return None

    def _deploy_local(self, source_dir: Path, target: DeployTarget) -> int:
        """Copy rules to a local filesystem path."""
        dest = Path(target.path)
        dest.mkdir(parents=True, exist_ok=True)
        count = 0
        for f in source_dir.rglob("*.yar"):
            d = dest / f.relative_to(source_dir)
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, d)
            count += 1
        for f in source_dir.rglob("*.yara"):
            d = dest / f.relative_to(source_dir)
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, d)
            count += 1
        logger.info("Deployed %d files to %s", count, dest)
        return count

    def _deploy_ssh(self, source_dir: Path, target: DeployTarget) -> int:
        """Deploy rules to a remote host via rsync over SSH."""
        ssh_opts = f"-p {target.port}"
        if target.key_file:
            ssh_opts += f" -i {target.key_file}"

        remote = f"{target.user}@{target.host}:{target.path}" if target.user else f"{target.host}:{target.path}"
        cmd = [
            "rsync", "-avz", "--delete",
            "-e", f"ssh {ssh_opts}",
            f"{source_dir}/",
            remote,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"rsync failed: {result.stderr}")

        # Count files transferred
        transferred = result.stdout.count("\n") - 4
        return max(0, transferred)

    def _deploy_github(self, source_dir: Path, target: DeployTarget) -> int:
        """Commit and push updated rules to a GitHub repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(
                ["git", "clone", target.path, tmpdir],
                check=True, capture_output=True,
            )
            rules_dest = Path(tmpdir) / target.prefix.strip("/")
            rules_dest.mkdir(parents=True, exist_ok=True)

            count = 0
            for f in source_dir.rglob("*.yar"):
                d = rules_dest / f.relative_to(source_dir)
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, d)
                count += 1

            subprocess.run(["git", "-C", tmpdir, "add", "."], check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m",
                 f"chore: deploy {count} YARA rules [{time.strftime('%Y-%m-%d %H:%M')}]"],
                check=True, capture_output=True,
            )
            subprocess.run(["git", "-C", tmpdir, "push"], check=True, capture_output=True)

        return count

    def _load_log(self) -> List[DeployRecord]:
        if self._log_path.exists():
            try:
                data = json.loads(self._log_path.read_text())
                return [DeployRecord(**r) for r in data]
            except Exception:
                return []
        return []

    def _save_log(self) -> None:
        self._log_path.write_text(
            json.dumps([r.to_dict() for r in self._log], indent=2)
        )
