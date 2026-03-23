# YaraForge

> **AI-powered YARA rule forge** for threat detection engineering.
> Generate, validate, and deploy YARA rules across Elastic, Splunk, and
> standalone YARA environments from a single CLI.

[![CI](https://github.com/rawqubit/yaraforge/actions/workflows/ci.yml/badge.svg)](https://github.com/rawqubit/yaraforge/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/rawqubit/yaraforge?style=flat-square)](https://github.com/rawqubit/yaraforge/stargazers)

---

## The Problem

Writing YARA rules is slow, inconsistent, and requires deep expertise.
Threat intel analysts spend hours hand-crafting rules that may still miss
variants. And deploying the same rule across Elastic SIEM, Splunk, and
standalone YARA means maintaining three different formats.

## What YaraForge Does

YaraForge uses AI to generate syntactically correct, semantically meaningful
YARA rules from natural language threat descriptions. It then validates them
against a clean corpus, tests for false positives, and deploys to your SIEM
of choice.

**Pipeline:**

```
Threat Intel Text -> AI Rule Generation -> Validation ->
False-Positive Testing -> SIEM Deployment

Targets: Elastic | Splunk | Standalone YARA
```

## Features

- **AI Rule Synthesis** - Generate YARA rules from threat intelligence
  text, malware reports, or plain English descriptions
- **Multi-target Deployment** - Deploy to Elastic Security, Splunk, or
  standalone YARA from a single command
- **Pre-built Rule Bundles** - Ships with curated rules for ransomware,
  webshells, and generic malware
- **Automated Validation** - Syntax checking and false-positive rate
  testing before deployment
- **Structured Rule Repository** - Organized by threat category

## Installation

```bash
git clone https://github.com/rawqubit/yaraforge.git
cd yaraforge
pip install -e .
```

## Quick Start

**Generate a rule from a threat description:**
```bash
yaraforge generate --description "Detect Cobalt Strike beacon using malleable C2 indicators"
```

**Validate your rule repository:**
```bash
yaraforge validate --rules rules/
```

**Deploy to Elastic Security:**
```bash
yaraforge deploy --target elastic --rules rules/malware/
```

**Run the full forge pipeline:**
```bash
yaraforge forge --input threat_report.txt --deploy elastic
```

## Repository Structure

```
yaraforge/
|-- engine/      # YARA rule loading, parsing, scanning
|-- cli/         # CLI entrypoints
|-- deploy/      # Deployment adapters (Elastic, Splunk, YARA)
|-- report/      # Output and reporting
`-- rules/
    |-- malware/
    |-- ransomware/
    `-- webshells/
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design.

## Requirements

- Python 3.10+
- OpenAI API key (`OPENAI_API_KEY`)
- `yara-python` for local validation

## Use Cases

- SOC teams generating detection rules from threat intel feeds
- Red teamers creating custom detection challenges
- Security engineers maintaining rule libraries across multiple SIEMs
- Automated rule generation in CI/CD pipelines

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

MIT (c) Srinikhil Chakilam
