#!/usr/bin/env python3
"""
install_hook.py — устанавливает pre-commit hook для guardrail.
Запускать из корня git-репозитория: python install_hook.py
"""

import os
import sys
import stat
from pathlib import Path

HOOK_CONTENT = """#!/bin/sh
# guardrail pre-commit hook
# Установлен через install_hook.py

# Получаем список staged файлов
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
    exit 0
fi

# Создаём временный список файлов для скана
TMPDIR=$(mktemp -d)
echo "$STAGED" | while read file; do
    if [ -f "$file" ]; then
        guardrail check "$file"
        if [ $? -ne 0 ]; then
            echo ""
            echo "🚨 guardrail blocked this commit."
            echo "   Fix the issues above or use: git commit --no-verify"
            rm -rf "$TMPDIR"
            exit 1
        fi
    fi
done

STATUS=$?
rm -rf "$TMPDIR"
exit $STATUS
"""


def install():
    git_dir = Path(".git")
    if not git_dir.exists():
        print("Error: not a git repository (no .git directory found)")
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        existing = hook_path.read_text()
        if "guardrail" in existing:
            print(f"✓ guardrail hook already installed at {hook_path}")
            return
        # Бэкап существующего хука
        backup = hook_path.with_suffix(".bak")
        hook_path.rename(backup)
        print(f"  Backed up existing hook to {backup}")

    hook_path.write_text(HOOK_CONTENT)

    # Делаем исполняемым
    current = stat.S_IMODE(os.lstat(hook_path).st_mode)
    os.chmod(hook_path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"✓ guardrail pre-commit hook installed at {hook_path}")
    print("  Every commit will now be scanned for security issues.")
    print("  To bypass: git commit --no-verify")


if __name__ == "__main__":
    install()
