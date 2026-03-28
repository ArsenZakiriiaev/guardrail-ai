from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


_IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
}

_SUSPICIOUS_PARAM_NAMES = {
    "alias",
    "clause",
    "column",
    "columns",
    "data",
    "direction",
    "expr",
    "expression",
    "field",
    "fields",
    "filter",
    "filters",
    "order",
    "payload",
    "query",
    "sort",
    "user_input",
    "value",
}

_SUSPICIOUS_ATTR_NAMES = {
    "alias",
    "clause",
    "column",
    "direction",
    "expr",
    "expression",
    "field",
    "filter",
    "filters",
    "fragment",
    "order",
    "query",
    "sort",
    "sql",
    "where",
}

_BUILDER_MUTATION_METHODS = {
    "add",
    "add_clause",
    "append",
    "filter",
    "group_by",
    "having",
    "join",
    "order_by",
    "select",
    "set_alias",
    "set_expression",
    "where",
}

_BUILDER_RENDER_METHODS = {"as_sql", "build", "compile", "render", "to_sql"}
_REQUEST_ATTRS = {"args", "cookies", "form", "headers", "json", "values"}
_EXECUTE_METHODS = {"execute", "executemany", "exec_driver_sql", "raw"}
_PERSISTENCE_METHODS = {"add", "commit", "flush", "save", "set"}


@dataclass
class _StoredValue:
    file: Path
    line: int
    field_names: set[str] = field(default_factory=set)


def analyze_python_heuristics(target: str | Path) -> list[dict]:
    target_path = Path(target).resolve()
    if not target_path.exists():
        return []

    root = target_path if target_path.is_dir() else target_path.parent
    files = [target_path] if target_path.is_file() else list(_iter_python_files(root))

    stored_values: list[_StoredValue] = []
    sink_results: list[dict] = []
    stored_field_names: set[str] = set()

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        file_stored = _find_persisted_request_values(tree, file_path)
        stored_values.extend(file_stored)
        for item in file_stored:
            stored_field_names.update(item.field_names)

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        sink_results.extend(_find_querybuilder_sinks(tree, source, file_path))
        if stored_field_names:
            sink_results.extend(_find_second_order_sqli_sinks(tree, source, file_path, stored_field_names))

    return _dedupe_results(sink_results)


def _iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in _IGNORE_DIRS for part in path.parts):
            continue
        yield path


def _find_persisted_request_values(tree: ast.AST, file_path: Path) -> list[_StoredValue]:
    findings: list[_StoredValue] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        tainted_names = _initial_tainted_names(node)
        persisted_fields: set[str] = set()
        saw_persistence = False

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                value_tainted = _expr_uses_names(child.value, tainted_names) or _expr_is_request_source(child.value)
                if value_tainted:
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            tainted_names.add(target.id)
                        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                            persisted_fields.add(target.attr)
                if isinstance(child.value, ast.Call):
                    keyword_fields = {
                        keyword.arg
                        for keyword in child.value.keywords
                        if keyword.arg and _expr_uses_names(keyword.value, tainted_names)
                    }
                    persisted_fields.update(keyword_fields)

            elif isinstance(child, ast.Call):
                attr_name = _call_attr_name(child)
                if attr_name in _PERSISTENCE_METHODS:
                    saw_persistence = True

        if saw_persistence and persisted_fields:
            findings.append(_StoredValue(file=file_path, line=node.lineno, field_names=persisted_fields))

    return findings


def _find_querybuilder_sinks(tree: ast.AST, source: str, file_path: Path) -> list[dict]:
    findings: list[dict] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        tainted_names = _initial_tainted_names(node)
        tainted_builders: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                target = child.targets[0]
                if isinstance(target, ast.Name):
                    if _expr_is_request_source(child.value) or _expr_uses_names(child.value, tainted_names):
                        tainted_names.add(target.id)
                    if isinstance(child.value, ast.Call) and _looks_like_builder_ctor(child.value):
                        tainted_builders.add(target.id)

            elif isinstance(child, ast.Call):
                attr_name = _call_attr_name(child)
                owner_name = _call_owner_name(child)
                if owner_name and owner_name in tainted_builders and attr_name in _BUILDER_MUTATION_METHODS:
                    if any(_expr_uses_names(argument, tainted_names) for argument in child.args):
                        tainted_builders.add(owner_name)

                if attr_name in _EXECUTE_METHODS and child.args:
                    if _expr_uses_tainted_builder_render(child.args[0], tainted_builders):
                        findings.append(
                            _make_result(
                                rule_id="rules.querybuilder-sqli",
                                message="Tainted QueryBuilder output flows into SQL execution.",
                                file_path=file_path,
                                line=child.lineno,
                                snippet=ast.get_source_segment(source, child) or _source_line(source, child.lineno),
                            )
                        )

    return findings


def _find_second_order_sqli_sinks(
    tree: ast.AST,
    source: str,
    file_path: Path,
    stored_field_names: set[str],
) -> list[dict]:
    findings: list[dict] = []
    for child in ast.walk(tree):
        if not isinstance(child, ast.Call):
            continue
        if _call_attr_name(child) not in _EXECUTE_METHODS or not child.args:
            continue
        arg = child.args[0]
        if not _looks_like_dynamic_sql(arg):
            continue

        attr_names = _attribute_names(arg)
        if not attr_names:
            continue

        suspicious = attr_names & (stored_field_names | _SUSPICIOUS_ATTR_NAMES)
        if not suspicious:
            continue

        findings.append(
            _make_result(
                rule_id="rules.second-order-sqli",
                message="Stored or indirect user-controlled data appears to flow into dynamic SQL execution.",
                file_path=file_path,
                line=child.lineno,
                snippet=ast.get_source_segment(source, child) or _source_line(source, child.lineno),
            )
        )

    return findings


def _initial_tainted_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = set()
    for argument in [*node.args.args, *node.args.kwonlyargs]:
        if argument.arg.lower() in _SUSPICIOUS_PARAM_NAMES:
            names.add(argument.arg)
    return names


def _expr_is_request_source(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
            if child.value.id == "request" and child.attr in _REQUEST_ATTRS:
                return True
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if isinstance(child.func.value, ast.Name) and child.func.value.id == "request":
                return True
    return False


def _expr_uses_names(node: ast.AST | None, names: set[str]) -> bool:
    if node is None or not names:
        return False
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _call_attr_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _call_owner_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return node.func.value.id
    return ""


def _looks_like_builder_ctor(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id.endswith("Builder") or "query" in node.func.id.lower()
    return False


def _expr_uses_tainted_builder_render(node: ast.AST, tainted_builders: set[str]) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        if child.func.attr not in _BUILDER_RENDER_METHODS:
            continue
        if isinstance(child.func.value, ast.Name) and child.func.value.id in tainted_builders:
            return True
    return False


def _looks_like_dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"format", "join"}:
            return True
    return False


def _attribute_names(node: ast.AST) -> set[str]:
    return {
        child.attr.lower()
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute)
    }


def _source_line(source: str, line_number: int) -> str:
    lines = source.splitlines()
    index = line_number - 1
    if 0 <= index < len(lines):
        return lines[index].strip()
    return ""


def _make_result(*, rule_id: str, message: str, file_path: Path, line: int, snippet: str) -> dict:
    return {
        "check_id": rule_id,
        "path": str(file_path),
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 1},
        "extra": {
            "message": message,
            "severity": "ERROR",
            "lines": snippet,
            "metadata": {"type": "code", "engine": "guardrail-heuristic"},
        },
    }


def _dedupe_results(results: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen = set()
    for item in results:
        key = (item.get("check_id"), item.get("path"), item.get("start", {}).get("line"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
