#!/usr/bin/env python3
"""Thin entry point so `python hannibal.py ...` keeps working.

The real CLI lives in hannibal/cli.py, which is also exposed as the installed
`hannibal` console command (pyproject.toml) and via `python -m hannibal`.
"""
from hannibal.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
