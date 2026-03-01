# YaraForge Architecture Overview

## System Architecture

```mermaid
graph TB
    subgraph Client["Client Layer"]
        CLI["CLI Interface<br/>(Command Line Tools)"]
    end
    
    subgraph Core["Core Processing Layer"]
        Engine["Engine Module<br/>(YARA Rule Processing)"]
        Compiler["Rule Compiler"]
        Validator["Rule Validator"]
    end
    
    subgraph Execution["Execution Layer"]
        Scanner["Scanner<br/>(Local & Remote)"]
        Deploy["Deployment Manager<br/>(Distribution)"]
    end
    
    subgraph Output["Output Layer"]
        Report["Report Generator<br/>(Results & Analytics)"]
    end
    
    subgraph Storage["Storage & Resources"]
        Rules["Rules Directory<br/>(YARA Rule Files)"]
        Tests["Test Suite<br/>(Unit & Integration Tests)"]
    end
    
    subgraph Targets["Target Systems"]
        LocalTarget["Local Targets"]
        RemoteTarget["Remote Targets"]
    end
    
    CLI -->|Commands| Engine
    CLI -->|Deploy Commands| Deploy
    CLI -->|Report Requests| Report
    
    Engine --> Compiler
    Engine --> Validator
    Engine -->|Compiled Rules| Scanner
    
    Scanner -->|Scan Rules| LocalTarget
    Scanner -->|Scan Rules| RemoteTarget
    
    Deploy -->|Distribute Rules| LocalTarget
    Deploy -->|Distribute Rules| RemoteTarget
    
    LocalTarget -->|Scan Results| Report
    RemoteTarget -->|Scan Results| Report
    
    Report -->|Generate Reports| CLI
    
    Rules -->|Rule Input| Engine
    Rules -->|Rule Input| Scanner
    Rules -->|Rule Input| Deploy
    
    Tests -->|Validate| Engine
    Tests -->|Validate| Scanner
    
    style Client fill:#e1f5ff
    style Core fill:#f3e5f5
    style Execution fill:#e8f5e9
    style Output fill:#fff3e0
    style Storage fill:#f5f5f5
    style Targets fill:#fce4ec

```

# yaraforge

**YARA rule deployment and scanning automation.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![YARA](https://img.shields.io/badge/YARA-4.3%2B-red)](https://virustotal.github.io/yara/)
[![Security](https://img.shields.io/badge/topic-infosec-blueviolet)](https://github.com/rawqubit/yaraforge)

`yaraforge` is a production-grade CLI tool for managing the full lifecycle of YARA rules — from loading and validation through multi-threaded scanning to deployment across local and remote targets. It is designed for security engineers who need a reliable, scriptable, CI/CD-friendly YARA automation layer.

---

## Features

- **Rule Management** — Load `.yar`/`.yara` files from local directories, remote URLs, or GitHub repositories with automatic syntax validation.
- **Fast Multi-threaded Scanning** — Scan files, directories (recursive), and process memory with a configurable thread pool.
- **Compiled Rule Bundles** — Compile rules to `.yarc` bundles for near-instant reloading in production pipelines.
- **Flexible Deployment** — Deploy rule sets to local paths or remote SSH hosts via `rsync`; sync from public/private GitHub repos.
- **Versioned Deployment History** — Every deployment is logged with SHA-256 bundle hashes, enabling one-command rollback.
- **Multiple Report Formats** — Output scan results as JSON, SARIF 2.1.0 (GitHub Code Scanning), HTML, CSV, or plain text.
- **CI/CD Ready** — Exits with code `1` on matches; SARIF output integrates directly with GitHub Advanced Security.
- **Bundled Rule Library** — Ships with detection rules for malware, ransomware, web shells, and network threats.

---

## Installation

```bash
# From PyPI (recommended)
pip install yaraforge

# From source
git clone https://github.com/rawqubit/yaraforge
cd yaraforge
pip install -e ".[dev]"
```

**System dependency:** YARA must be installed on the system.

```bash
# Ubuntu/Debian
sudo apt install yara

# macOS
brew install yara
```

---

## Quick Start

### Validate rules

```bash
yaraforge validate ./rules/
# ✓ generic_malware.yar (4 rules)
# ✓ ransomware_generic.yar (4 rules)
# ✓ webshell_generic.yar (4 rules)
# 3/3 files valid.
```

### Scan a directory

```bash
yaraforge scan /var/www/html --rules ./rules/ --format text
```

### Scan and output SARIF for GitHub Code Scanning

```bash
yaraforge scan ./src --rules ./rules/ --format sarif --output results.sarif
```

### Compile rules to a bundle

```bash
yaraforge compile ./rules/ --output compiled.yarc
# [✓] Compiled 12 rules → compiled.yarc (14.2 KB, 3.1ms)
```

### Sync rules from GitHub

```bash
yaraforge sync Yara-Rules/rules --dest ./rules/ --branch main
# [✓] Synced 847 rule files to ./rules/
```

### Deploy rules to a remote host

```bash
yaraforge deploy ./rules/ \
  --target-type ssh \
  --target-path /opt/yara/rules \
  --host scanner.internal \
  --user deploy \
  --key-file ~/.ssh/id_ed25519
```

### Scan a running process

```bash
sudo yaraforge scan --rules ./rules/ --pid 1234
```

---

## CLI Reference

```
Usage: yaraforge [OPTIONS] COMMAND [ARGS]...

Options:
  --verbose, -v   Enable debug logging.
  --version       Show version and exit.

Commands:
  scan      Scan files, directories, or processes for YARA matches.
  validate  Validate YARA rule syntax without scanning.
  compile   Compile rules into a fast .yarc bundle.
  sync      Pull rules from a GitHub repository.
  deploy    Deploy rules to a local path or remote SSH host.
  report    Convert an existing JSON scan report to another format.
```

### `scan` options

| Flag | Default | Description |
|------|---------|-------------|
| `--rules, -r` | required | Rule file or directory (repeatable) |
| `--recursive` | `true` | Recursively scan directories |
| `--threads, -t` | `4` | Scanner thread count |
| `--max-size` | `50` MB | Max file size to scan |
| `--timeout` | `60` s | Per-file scan timeout |
| `--format, -f` | `text` | Output format: `json`, `sarif`, `html`, `csv`, `text` |
| `--output, -o` | stdout | Write report to file |
| `--pid` | — | Scan a running process by PID |
| `--exit-code` | `true` | Exit 1 if matches found |

---

## Report Formats

| Format | Use Case |
|--------|----------|
| `text` | Human-readable terminal summary |
| `json` | Machine-readable full detail, pipeline integration |
| `sarif` | GitHub Code Scanning, VS Code SARIF Viewer |
| `html` | Self-contained report for sharing |
| `csv` | Spreadsheet analysis |

### GitHub Code Scanning Integration

Add to `.github/workflows/yara-scan.yml`:

```yaml
name: YARA Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install yaraforge
      - run: |
          yaraforge scan . \
            --rules rules/ \
            --format sarif \
            --output yara-results.sarif \
            --no-exit-code
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: yara-results.sarif
```

---

## Bundled Rules

`yaraforge` ships with a curated rule library under `rules/`:

| Category | Rules | Description |
|----------|-------|-------------|
| `malware/` | 4 | Generic malware patterns, shellcode stubs, C2 beacons |
| `ransomware/` | 4 | Ransom notes, file encryption APIs, WannaCry IoCs |
| `webshells/` | 4 | PHP, ASPX, JavaScript web shell detection |
| `network/` | — | Network-level threat indicators |

---

## Architecture

```
yaraforge/
├── engine/
│   ├── loader.py      # Rule loading, validation, compilation
│   └── scanner.py     # Multi-threaded file/process/memory scanning
├── deploy/
│   └── deployer.py    # Rule deployment, versioning, rollback
├── report/
│   └── reporter.py    # JSON, SARIF, HTML, CSV, text output
└── cli/
    └── main.py        # Click CLI entrypoint
```



---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=yaraforge

# Lint
ruff check yaraforge/

# Type check
mypy yaraforge/
```

---

## License

MIT — see [LICENSE](LICENSE).
