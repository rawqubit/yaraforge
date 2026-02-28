"""
yaraforge.engine.loader
~~~~~~~~~~~~~~~~~~~~~~~
Rule loading, validation, and compilation engine.
Supports single files, directories, and remote rule sources (GitHub, URLs).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import urlretrieve

import yara

logger = logging.getLogger(__name__)


@dataclass
class RuleMetadata:
    """Metadata extracted from a YARA rule file."""
    path: str
    name: str
    sha256: str
    rule_count: int
    tags: List[str] = field(default_factory=list)
    loaded_at: float = field(default_factory=time.time)
    source: str = "local"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CompileResult:
    """Result of a rule compilation attempt."""
    success: bool
    rules: Optional[yara.Rules] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    rule_count: int = 0
    compile_time_ms: float = 0.0


class RuleLoader:
    """
    Loads, validates, and compiles YARA rules from multiple sources.

    Supports:
    - Single .yar / .yara files
    - Directories (recursive or flat)
    - Remote URLs (raw GitHub, HTTP/S)
    - Compiled rule bundles (.yarc)
    - Rule namespace isolation
    """

    VALID_EXTENSIONS = {".yar", ".yara", ".rule"}
    COMPILED_EXTENSION = ".yarc"

    def __init__(
        self,
        rule_dirs: Optional[List[str]] = None,
        cache_dir: Optional[str] = None,
        strict: bool = False,
    ):
        self.rule_dirs = [Path(d) for d in (rule_dirs or [])]
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".yaraforge" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.strict = strict
        self._loaded_rules: Dict[str, RuleMetadata] = {}
        self._compiled: Optional[yara.Rules] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(self, path: str | Path, namespace: Optional[str] = None) -> RuleMetadata:
        """Load and validate a single YARA rule file."""
        path = Path(path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")
        if path.suffix not in self.VALID_EXTENSIONS:
            raise ValueError(f"Unsupported extension '{path.suffix}'. Use: {self.VALID_EXTENSIONS}")

        content = path.read_text(encoding="utf-8")
        sha256 = hashlib.sha256(content.encode()).hexdigest()
        rule_count = self._count_rules(content)
        tags = self._extract_tags(content)
        ns = namespace or path.stem

        # Validate syntax
        try:
            yara.compile(filepaths={ns: str(path)})
        except yara.SyntaxError as exc:
            raise ValueError(f"YARA syntax error in {path}: {exc}") from exc

        meta = RuleMetadata(
            path=str(path),
            name=path.stem,
            sha256=sha256,
            rule_count=rule_count,
            tags=tags,
            source="local",
        )
        self._loaded_rules[str(path)] = meta
        self._compiled = None  # invalidate cache
        logger.info("Loaded rule file: %s (%d rules)", path.name, rule_count)
        return meta

    def load_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        namespace_prefix: str = "",
    ) -> List[RuleMetadata]:
        """Load all YARA rules from a directory."""
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        pattern = "**/*" if recursive else "*"
        files = [
            f for f in directory.glob(pattern)
            if f.is_file() and f.suffix in self.VALID_EXTENSIONS
        ]
        files.sort()

        results = []
        for f in files:
            ns = f"{namespace_prefix}/{f.stem}" if namespace_prefix else f.stem
            try:
                meta = self.load_file(f, namespace=ns)
                results.append(meta)
            except (ValueError, FileNotFoundError) as exc:
                if self.strict:
                    raise
                logger.warning("Skipping %s: %s", f.name, exc)

        logger.info("Loaded %d rule files from %s", len(results), directory)
        return results

    def load_url(self, url: str, namespace: Optional[str] = None) -> RuleMetadata:
        """Download and load a YARA rule from a remote URL."""
        cache_key = hashlib.sha256(url.encode()).hexdigest()[:16]
        cached = self.cache_dir / f"{cache_key}.yar"

        if not cached.exists():
            logger.info("Downloading rule from %s", url)
            urlretrieve(url, cached)  # noqa: S310

        return self.load_file(cached, namespace=namespace or cache_key)

    def compile(self, externals: Optional[Dict] = None) -> CompileResult:
        """
        Compile all loaded rules into a single yara.Rules object.
        Returns a CompileResult with timing and diagnostics.
        """
        if not self._loaded_rules:
            return CompileResult(success=False, error="No rules loaded")

        filepaths: Dict[str, str] = {}
        for path_str, meta in self._loaded_rules.items():
            filepaths[meta.name] = path_str

        start = time.perf_counter()
        try:
            rules = yara.compile(
                filepaths=filepaths,
                externals=externals or {},
            )
            elapsed = (time.perf_counter() - start) * 1000
            total_rules = sum(m.rule_count for m in self._loaded_rules.values())
            self._compiled = rules
            logger.info(
                "Compiled %d rules from %d files in %.1fms",
                total_rules, len(filepaths), elapsed,
            )
            return CompileResult(
                success=True,
                rules=rules,
                rule_count=total_rules,
                compile_time_ms=elapsed,
            )
        except yara.SyntaxError as exc:
            return CompileResult(success=False, error=str(exc))
        except yara.Error as exc:
            return CompileResult(success=False, error=f"YARA error: {exc}")

    def save_compiled(self, output_path: str | Path) -> Path:
        """Save compiled rules to a .yarc bundle for fast reloading."""
        if self._compiled is None:
            result = self.compile()
            if not result.success:
                raise RuntimeError(f"Compilation failed: {result.error}")
        output_path = Path(output_path)
        self._compiled.save(str(output_path))
        logger.info("Saved compiled rules to %s", output_path)
        return output_path

    def load_compiled(self, path: str | Path) -> yara.Rules:
        """Load a pre-compiled .yarc bundle."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Compiled bundle not found: {path}")
        self._compiled = yara.load(str(path))
        logger.info("Loaded compiled bundle: %s", path.name)
        return self._compiled

    def get_compiled(self) -> Optional[yara.Rules]:
        return self._compiled

    def list_loaded(self) -> List[RuleMetadata]:
        return list(self._loaded_rules.values())

    def export_manifest(self, output_path: str | Path) -> None:
        """Export a JSON manifest of all loaded rules."""
        manifest = {
            "generated_at": time.time(),
            "rule_count": len(self._loaded_rules),
            "rules": [m.to_dict() for m in self._loaded_rules.values()],
        }
        Path(output_path).write_text(json.dumps(manifest, indent=2))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_rules(content: str) -> int:
        """Count the number of rule definitions in a YARA source string."""
        return len(re.findall(r"^\s*rule\s+\w+", content, re.MULTILINE))

    @staticmethod
    def _extract_tags(content: str) -> List[str]:
        """Extract tags from rule definitions."""
        tags: List[str] = []
        for match in re.finditer(r"rule\s+\w+\s*:\s*([\w\s]+)\s*\{", content):
            tags.extend(match.group(1).split())
        return list(set(tags))
