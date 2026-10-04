# Contributing to qv

Thank you for contributing to `qv`!

Please check our detailed [Contributor Guide](docs/contributing.md) for instructions on setting up your local environment, running tests, and adding new diagnostic rules.

## Code of Conduct

All participants in the `qv` project agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand expectations for all contributors.

## Reporting Security Issues

If you discover a security vulnerability, please refer to our [Security Policy](SECURITY.md). Do not report security vulnerabilities via public GitHub issues.

## Quick Commands

```bash
# Setup
uv sync --all-extras

# Run test suite
uv run pytest

# Format and lint
uv run ruff check .
uv run ruff format .

# Type checking
uv run pyright
```
