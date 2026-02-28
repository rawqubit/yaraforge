"""
yaraforge.engine.scanner
~~~~~~~~~~~~~~~~~~~~~~~~
High-performance YARA scanner with multi-target support, threading,
process memory scanning, and streaming file scanning.
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional, Set

import yara

logger = logging.getLogger(__name__)

# Maximum file size to scan in bytes (default: 50 MB)
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024
# YARA scan timeout per file in seconds
DEFAULT_TIMEOUT = 60


@dataclass
class StringMatch:
    """A single string match within a YARA rule."""
    identifier: str
    offset: int
    data: bytes

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "offset": self.offset,
            "data": self.data.hex(),
            "data_ascii": self.data.decode("ascii", errors="replace"),
        }


@dataclass
class RuleMatch:
    """A single YARA rule match against a target."""
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict
    strings: List[StringMatch]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "strings": [s.to_dict() for s in self.strings],
        }


@dataclass
class ScanResult:
    """Result of scanning a single target."""
    target: str
    target_type: str  # "file", "process", "memory", "url"
    scanned_at: float = field(default_factory=time.time)
    matches: List[RuleMatch] = field(default_factory=list)
    error: Optional[str] = None
    scan_time_ms: float = 0.0
    file_size: int = 0
    sha256: Optional[str] = None
    skipped: bool = False
    skip_reason: Optional[str] = None

    @property
    def is_clean(self) -> bool:
        return len(self.matches) == 0 and not self.error

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "scanned_at": self.scanned_at,
            "matches": [m.to_dict() for m in self.matches],
            "error": self.error,
            "scan_time_ms": self.scan_time_ms,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "is_clean": self.is_clean,
            "match_count": self.match_count,
        }


@dataclass
class ScanSummary:
    """Aggregated summary of a scanning session."""
    total_targets: int = 0
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    matches: int = 0
    clean: int = 0
    total_bytes: int = 0
    elapsed_seconds: float = 0.0
    results: List[ScanResult] = field(default_factory=list)

    @property
    def matched_targets(self) -> List[ScanResult]:
        return [r for r in self.results if r.match_count > 0]

    def to_dict(self) -> dict:
        return {
            "total_targets": self.total_targets,
            "scanned": self.scanned,
            "skipped": self.skipped,
            "errors": self.errors,
            "matches": self.matches,
            "clean": self.clean,
            "total_bytes": self.total_bytes,
            "elapsed_seconds": self.elapsed_seconds,
            "throughput_mb_s": (
                (self.total_bytes / 1024 / 1024) / self.elapsed_seconds
                if self.elapsed_seconds > 0 else 0
            ),
            "results": [r.to_dict() for r in self.results],
        }


class Scanner:
    """
    High-performance YARA scanner.

    Features:
    - Multi-threaded file scanning
    - Process memory scanning (Linux)
    - Streaming large file support
    - Configurable file size limits and timeouts
    - Extension and path exclusion filters
    - Progress callbacks
    """

    def __init__(
        self,
        rules: yara.Rules,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        timeout: int = DEFAULT_TIMEOUT,
        threads: int = 4,
        exclude_extensions: Optional[Set[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        externals: Optional[Dict] = None,
    ):
        self.rules = rules
        self.max_file_size = max_file_size
        self.timeout = timeout
        self.threads = threads
        self.exclude_extensions = exclude_extensions or {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4",
            ".avi", ".mov", ".zip", ".tar", ".gz", ".bz2", ".7z",
        }
        self.exclude_paths = [Path(p) for p in (exclude_paths or [])]
        self.externals = externals or {}

    # ------------------------------------------------------------------
    # Public scanning API
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> ScanResult:
        """Scan a single file and return a ScanResult."""
        path = Path(path).resolve()
        result = ScanResult(target=str(path), target_type="file")

        # Pre-scan checks
        if not path.exists():
            result.error = "File not found"
            return result
        if not path.is_file():
            result.error = "Not a regular file"
            return result
        if path.suffix.lower() in self.exclude_extensions:
            result.skipped = True
            result.skip_reason = f"Excluded extension: {path.suffix}"
            return result
        if any(path.is_relative_to(ep) for ep in self.exclude_paths if ep.exists()):
            result.skipped = True
            result.skip_reason = "Excluded path"
            return result

        file_size = path.stat().st_size
        result.file_size = file_size

        if file_size > self.max_file_size:
            result.skipped = True
            result.skip_reason = f"File too large ({file_size / 1024 / 1024:.1f} MB > {self.max_file_size / 1024 / 1024:.0f} MB limit)"
            return result

        # Compute SHA-256
        try:
            result.sha256 = self._sha256_file(path)
        except OSError:
            pass

        # Scan
        start = time.perf_counter()
        try:
            raw_matches = self.rules.match(
                str(path),
                timeout=self.timeout,
                externals=self.externals,
            )
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            result.matches = self._parse_matches(raw_matches)
        except yara.TimeoutError:
            result.error = f"Scan timed out after {self.timeout}s"
        except yara.Error as exc:
            result.error = str(exc)
        except PermissionError:
            result.error = "Permission denied"

        return result

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        progress_callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanSummary:
        """
        Scan all files in a directory using a thread pool.
        Calls progress_callback(result) after each file is scanned.
        """
        directory = Path(directory).resolve()
        pattern = "**/*" if recursive else "*"
        files = [f for f in directory.glob(pattern) if f.is_file()]

        summary = ScanSummary(total_targets=len(files))
        start = time.perf_counter()

        file_queue: queue.Queue[Path] = queue.Queue()
        result_lock = threading.Lock()

        for f in files:
            file_queue.put(f)

        def worker():
            while True:
                try:
                    f = file_queue.get_nowait()
                except queue.Empty:
                    break
                result = self.scan_file(f)
                with result_lock:
                    summary.results.append(result)
                    if result.skipped:
                        summary.skipped += 1
                    elif result.error:
                        summary.errors += 1
                    else:
                        summary.scanned += 1
                        summary.total_bytes += result.file_size
                        if result.match_count > 0:
                            summary.matches += result.match_count
                        else:
                            summary.clean += 1
                if progress_callback:
                    progress_callback(result)
                file_queue.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        summary.elapsed_seconds = time.perf_counter() - start
        logger.info(
            "Scan complete: %d files, %d matches, %d errors in %.2fs",
            summary.scanned, summary.matches, summary.errors, summary.elapsed_seconds,
        )
        return summary

    def scan_process(self, pid: int) -> ScanResult:
        """
        Scan a running process's memory (Linux only, requires root or ptrace).
        Reads /proc/<pid>/mem via maps.
        """
        result = ScanResult(target=f"pid:{pid}", target_type="process")
        maps_path = Path(f"/proc/{pid}/maps")
        mem_path = Path(f"/proc/{pid}/mem")

        if not maps_path.exists():
            result.error = f"Process {pid} not found or not accessible"
            return result

        start = time.perf_counter()
        try:
            raw_matches = self.rules.match(pid=pid, timeout=self.timeout)
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            result.matches = self._parse_matches(raw_matches)
        except yara.TimeoutError:
            result.error = f"Process scan timed out after {self.timeout}s"
        except yara.Error as exc:
            result.error = str(exc)
        except PermissionError:
            result.error = f"Permission denied scanning PID {pid}. Try running as root."

        return result

    def scan_bytes(self, data: bytes, label: str = "<memory>") -> ScanResult:
        """Scan raw bytes (e.g. network payload, decrypted buffer)."""
        result = ScanResult(target=label, target_type="memory")
        result.file_size = len(data)
        result.sha256 = hashlib.sha256(data).hexdigest()

        start = time.perf_counter()
        try:
            raw_matches = self.rules.match(data=data, timeout=self.timeout)
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            result.matches = self._parse_matches(raw_matches)
        except yara.TimeoutError:
            result.error = f"Scan timed out after {self.timeout}s"
        except yara.Error as exc:
            result.error = str(exc)

        return result

    def stream_results(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> Generator[ScanResult, None, None]:
        """Generator that yields ScanResult objects as files are scanned."""
        directory = Path(directory).resolve()
        pattern = "**/*" if recursive else "*"
        for f in sorted(directory.glob(pattern)):
            if f.is_file():
                yield self.scan_file(f)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _parse_matches(raw_matches: list) -> List[RuleMatch]:
        matches = []
        for m in raw_matches:
            strings = [
                StringMatch(
                    identifier=s.identifier,
                    offset=s.instances[0].offset if s.instances else 0,
                    data=bytes(s.instances[0].matched_data) if s.instances else b"",
                )
                for s in m.strings
            ]
            matches.append(RuleMatch(
                rule=m.rule,
                namespace=m.namespace,
                tags=list(m.tags),
                meta=dict(m.meta),
                strings=strings,
            ))
        return matches
