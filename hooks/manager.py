"""
hooks/manager.py — установка и управление git-хуками.
Устанавливает pre-commit и pre-push хуки, которые блокируют
опасный код до попадания в репозиторий.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console(stderr=True)


_PRE_COMMIT_TEMPLATE = """\
#!/usr/bin/env bash
# ──────────────────────────────────────────────
# Guardrail-AI pre-commit hook
# Blocks commits containing security issues.
# ──────────────────────────────────────────────

# Path to guardrail binary (set at install time)
GUARDRAIL_BIN="{{GUARDRAIL_BIN}}"

# Fallback: search PATH
if [ ! -x "$GUARDRAIL_BIN" ]; then
    GUARDRAIL_BIN=$(command -v guardrail 2>/dev/null || true)
fi
if [ -z "$GUARDRAIL_BIN" ]; then
    echo "⚠️  Guardrail not found. Skipping check."
    exit 0
fi

# Collect staged Python files
STAGED_PY=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.py$' || true)

if [ -z "$STAGED_PY" ]; then
    exit 0
fi

echo ""
echo "🛡️  Guardrail: проверяю staged файлы..."
echo ""

# Create temp directory for staged content
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

FAIL=0
FAIL_FILES=""
for FILE in $STAGED_PY; do
    # Extract staged version (not working tree version)
    STAGED_CONTENT=$(git show ":$FILE" 2>/dev/null || true)
    if [ -z "$STAGED_CONTENT" ]; then
        continue
    fi

    # Write staged content to temp file preserving path structure
    TMPFILE="$TMPDIR/$FILE"
    mkdir -p "$(dirname "$TMPFILE")"
    echo "$STAGED_CONTENT" > "$TMPFILE"

    # Run guardrail check on the staged version
    OUTPUT=$("$GUARDRAIL_BIN" check "$TMPFILE" 2>&1)
    EXIT_CODE=$?

    if [ "$EXIT_CODE" -eq 1 ]; then
        echo "  ❌ $FILE"
        echo "$OUTPUT" | sed "s|$TMPDIR/||g" | sed 's/^/     /'
        echo ""
        FAIL=1
        FAIL_FILES="$FAIL_FILES $FILE"
    fi
done

if [ "$FAIL" -eq 1 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🚫 Коммит заблокирован Guardrail."
    echo ""
    echo "   Проблемные файлы:$FAIL_FILES"
    echo ""
    echo "   Чтобы увидеть детали + AI-фикс:"
    echo "     guardrail scan <file>"
    echo ""
    echo "   Чтобы обойти (не рекомендуется):"
    echo "     git commit --no-verify"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

echo "  ✅ Всё чисто — коммит разрешён."
exit 0
"""

_PRE_PUSH_TEMPLATE = """\
#!/usr/bin/env bash
# ──────────────────────────────────────────────
# Guardrail-AI pre-push hook
# Scans changed files before push.
# ──────────────────────────────────────────────

# Path to guardrail binary (set at install time)
GUARDRAIL_BIN="{{GUARDRAIL_BIN}}"

# Fallback: search PATH
if [ ! -x "$GUARDRAIL_BIN" ]; then
    GUARDRAIL_BIN=$(command -v guardrail 2>/dev/null || true)
fi
if [ -z "$GUARDRAIL_BIN" ]; then
    echo "⚠️  Guardrail not found. Skipping check."
    exit 0
fi

# Read push info from stdin
while read local_ref local_sha remote_ref remote_sha; do
    # Find files changed between local and remote
    if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
        CHANGED_PY=$(git diff --name-only HEAD --diff-filter=ACM 2>/dev/null | grep -E '\\.py$' || true)
    else
        CHANGED_PY=$(git diff --name-only "$remote_sha" "$local_sha" --diff-filter=ACM 2>/dev/null | grep -E '\\.py$' || true)
    fi

    if [ -z "$CHANGED_PY" ]; then
        continue
    fi

    echo ""
    echo "🛡️  Guardrail: проверяю файлы перед push..."
    echo ""

    FAIL=0
    for FILE in $CHANGED_PY; do
        if [ -f "$FILE" ]; then
            OUTPUT=$("$GUARDRAIL_BIN" check "$FILE" 2>&1)
            if [ $? -eq 1 ]; then
                echo "  ❌ $FILE"
                echo "$OUTPUT" | sed 's/^/     /'
                FAIL=1
            fi
        fi
    done

    if [ "$FAIL" -eq 1 ]; then
        echo ""
        echo "🚫 Push заблокирован Guardrail."
        echo "   Исправь проблемы или: git push --no-verify"
        exit 1
    fi

    echo "  ✅ Push разрешён."
done

exit 0
"""


def find_git_root(start: str | Path | None = None) -> Optional[Path]:
    """Находит корень git-репозитория."""
    cwd = None
    if start:
        p = Path(start)
        cwd = str(p if p.is_dir() else p.parent)

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=cwd,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except FileNotFoundError:
        pass
    return None


def _resolve_guardrail_bin() -> str:
    """Find the guardrail binary path to embed in hook scripts."""
    # 1. Check next to the current Python executable
    python_dir = Path(sys.executable).parent
    candidate = python_dir / "guardrail"
    if candidate.is_file():
        return str(candidate.resolve())
    # 2. Check shutil which (searches PATH)
    found = shutil.which("guardrail")
    if found:
        return str(Path(found).resolve())
    # 3. Fallback — just the name, hope it's in PATH at commit time
    return "guardrail"


def install_hooks(project_root: str | Path | None = None) -> tuple[bool, str]:
    """
    Устанавливает pre-commit и pre-push хуки.
    Возвращает (success, message).
    """
    git_root = find_git_root(project_root)
    if not git_root:
        return False, "Not a git repository. Run 'git init' first."

    hooks_dir = git_root / ".git" / "hooks"
    if not hooks_dir.is_dir():
        return False, f"Git hooks directory not found: {hooks_dir}"

    guardrail_bin = _resolve_guardrail_bin()
    installed = []

    templates = [
        ("pre-commit", _PRE_COMMIT_TEMPLATE),
        ("pre-push", _PRE_PUSH_TEMPLATE),
    ]

    for name, template in templates:
        content = template.replace("{{GUARDRAIL_BIN}}", guardrail_bin)
        hook_path = hooks_dir / name
        backup_path = hooks_dir / f"{name}.backup"

        if hook_path.exists():
            existing = hook_path.read_text()
            if "Guardrail-AI" in existing:
                installed.append(f"{name} (already installed)")
                continue

            hook_path.rename(backup_path)
            installed.append(f"{name} (existing hook backed up to {name}.backup)")
        else:
            installed.append(name)

        hook_path.write_text(content)
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC)

    return True, "Installed: " + ", ".join(installed)


def uninstall_hooks(project_root: str | Path | None = None) -> tuple[bool, str]:
    """
    Удаляет guardrail хуки.
    Восстанавливает .backup версии если есть.
    """
    git_root = find_git_root(project_root)
    if not git_root:
        return False, "Not a git repository."

    hooks_dir = git_root / ".git" / "hooks"
    removed = []

    for name in ("pre-commit", "pre-push"):
        hook_path = hooks_dir / name
        backup_path = hooks_dir / f"{name}.backup"

        if hook_path.exists():
            content = hook_path.read_text()
            if "Guardrail-AI" not in content:
                continue

            hook_path.unlink()

            if backup_path.exists():
                backup_path.rename(hook_path)
                removed.append(f"{name} (restored backup)")
            else:
                removed.append(name)

    if not removed:
        return True, "No guardrail hooks found."

    return True, "Removed: " + ", ".join(removed)


def hooks_status(project_root: str | Path | None = None) -> dict[str, str]:
    """Возвращает статус хуков: installed / not_installed / other."""
    git_root = find_git_root(project_root)
    if not git_root:
        return {"pre-commit": "no_git", "pre-push": "no_git"}

    hooks_dir = git_root / ".git" / "hooks"
    status = {}

    for name in ("pre-commit", "pre-push"):
        hook_path = hooks_dir / name
        if not hook_path.exists():
            status[name] = "not_installed"
        elif "Guardrail-AI" in hook_path.read_text():
            status[name] = "installed"
        else:
            status[name] = "other"

    return status
