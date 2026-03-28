from __future__ import annotations

from pathlib import Path


def read_code_context(path: str, line: int, before: int = 3, after: int = 3) -> str:
    if not path or line < 1:
        return ""

    try:
        source_lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""

    if not source_lines:
        return ""

    start_index = max(0, line - 1 - max(0, before))
    end_index = min(len(source_lines), line + max(0, after))

    context_lines: list[str] = []
    for index in range(start_index, end_index):
        marker = ">" if index == line - 1 else " "
        context_lines.append(f"{marker} {index + 1}: {source_lines[index]}")

    return "\n".join(context_lines)
