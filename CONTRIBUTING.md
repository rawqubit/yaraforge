# Contributing to yaraforge

Thank you for your interest in contributing! Contributions of all kinds are welcome — bug reports, new YARA rules, feature requests, and pull requests.

## Getting Started

```bash
git clone https://github.com/rawqubit/yaraforge
cd yaraforge
pip install -e ".[dev]"
```

## Submitting Rules

New YARA rules should be placed in the appropriate `rules/` subdirectory. Each rule must include:
- A `description` meta field
- A `severity` meta field (`low`, `medium`, `high`, `critical`)
- A `reference` meta field where applicable

Run `yaraforge validate rules/` before submitting to ensure syntax is valid.

## Code Style

- Format with `black`
- Lint with `ruff`
- Type-check with `mypy`
- All new features must include tests in `tests/`

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Write tests for your changes.
3. Ensure `pytest tests/ -v` passes.
4. Submit a pull request with a clear description.
