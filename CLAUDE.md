# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a minimal Python project (`vuln`) scaffolded with `uv`, targeting Python 3.11+. It currently contains a single `main.py` entry point.

## Commands

This project uses `uv` for dependency and environment management.

```bash
# Install dependencies (including dev)
uv sync --dev

# Run the project
uv run python main.py

# Run tests
uv run pytest

# Run a single test file or test
uv run pytest path/to/test_file.py::test_name
```
