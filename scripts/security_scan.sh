#!/bin/bash
set -euo pipefail
echo "=== RAGIN Security Scan ==="
echo ""
echo "1. Bandit (Python SAST)..."
if command -v bandit &>/dev/null; then
    bandit -r ragin/ -f json -o bandit-report.json 2>&1 || echo "  [WARN] Bandit found issues — see bandit-report.json"
else
    echo "  [SKIP] bandit not installed — pip install bandit"
fi
echo ""
echo "2. Safety / pip-audit (dependency check)..."
if command -v pip-audit &>/dev/null; then
    pip-audit 2>&1 || echo "  [WARN] pip-audit found issues"
elif command -v safety &>/dev/null; then
    safety check 2>&1 || echo "  [WARN] safety found issues"
else
    echo "  [SKIP] Neither pip-audit nor safety installed"
fi
echo ""
echo "3. Ruff (lint)..."
if command -v ruff &>/dev/null; then
    ruff check ragin/ 2>&1 || echo "  [WARN] Ruff found lint issues"
else
    echo "  [SKIP] ruff not installed — pip install ruff"
fi
echo ""
echo "4. Mypy (type check)..."
if command -v mypy &>/dev/null; then
    mypy ragin/ --ignore-missing-imports 2>&1 || echo "  [WARN] Mypy found type issues"
else
    echo "  [SKIP] mypy not installed — pip install mypy"
fi
echo ""
echo "=== Scan Complete ==="
