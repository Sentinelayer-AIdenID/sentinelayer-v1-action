from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import re
import tokenize
from .pattern_scanner import _truncate_snippet


def bounded_python_deadline_loops(content: str) -> set[int]:
    """Recognize a narrow, dominating monotonic deadline/exit pattern.

    Unknown Python or a deadline reset/early continue stays unclassified. This
    avoids treating arbitrary appearances of the word 'deadline' as a bound.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, RecursionError):
        return set()
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Constant) and type(node.value.value) in {int, float} and 0 < node.value.value < 86400:
                constants[node.targets[0].id] = node.value.value

    def clock(node):
        if isinstance(node, ast.Call) and not node.args and not node.keywords and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "time" and node.func.attr in {"monotonic", "perf_counter"}:
                return node.func.attr
        return None

    bounded = set()
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        deadlines = {}
        for statement in function.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                name = statement.targets[0].id
                deadlines.pop(name, None)
                value = statement.value
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add) and clock(value.left):
                    timeout = value.right.value if isinstance(value.right, ast.Constant) else constants.get(value.right.id) if isinstance(value.right, ast.Name) else None
                    if type(timeout) in {int, float} and 0 < timeout < 86400:
                        deadlines[name] = clock(value.left)
                continue
            if not isinstance(statement, ast.While) or not isinstance(statement.test, ast.Constant) or statement.test.value is not True:
                # A conditional reassignment does not establish a dominating bound.
                for part in ast.walk(statement):
                    if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store):
                        deadlines.pop(part.id, None)
                continue
            writes = {part.id for part in ast.walk(statement) if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
            for guard in statement.body:
                if any(isinstance(part, ast.Continue) for part in ast.walk(guard)):
                    break
                if not isinstance(guard, ast.If) or not isinstance(guard.test, ast.Compare):
                    continue
                condition = guard.test
                if len(condition.ops) != 1 or not isinstance(condition.ops[0], (ast.Gt, ast.GtE)):
                    continue
                target = condition.comparators[0]
                if isinstance(target, ast.Name) and target.id not in writes and deadlines.get(target.id) == clock(condition.left) and clock(condition.left):
                    if any(isinstance(exit_node, (ast.Return, ast.Raise, ast.Break)) for exit_node in guard.body):
                        bounded.add(statement.lineno)
    return bounded

@dataclass(frozen=True)
class PythonHttpxCall:
    function_name: str
    line_start: int
    line_end: int
    has_timeout: bool


@dataclass(frozen=True)
class _RecoveredPythonStatement:
    line_number: int
    scope_key: tuple[int, ...]
    function_name: str | None
    tree: ast.Module
    parents: dict[ast.AST, ast.AST]


_HTTPX_FUNCTION_NAMES = frozenset(
    {
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.AsyncClient",
        "httpx.Client",
    }
)
_HTTPX_FUNCTION_NAMES_BY_CASEFOLD = {
    function_name.casefold(): function_name for function_name in _HTTPX_FUNCTION_NAMES
}
_MAX_FALLBACK_CALL_TOKENS = 512
_SQL_LEADING_COMMENTS_PATTERN = (
    r"(?:(?:/\*[\s\S]{0,1000}?\*/|--[^\r\n]*(?:\r?\n|$))\s*)*"
)


def _sql_statement_pattern(
    expression_pattern: str,
    *,
    include_contextual_select_expression: bool,
    statement_end_pattern: str,
) -> str:
    contextual_select_expression = (
        rf"| (?=[\s\S]{{0,4096}}{expression_pattern})"
        rf"[\s\S]{{1,4096}}{statement_end_pattern}"
        if include_contextual_select_expression
        else ""
    )
    return rf"""
    (?:
        SELECT\s+(?:
            [\s\S]{{0,4096}}\bFROM\b
            {contextual_select_expression}
            | [A-Za-z_][A-Za-z0-9_$.]*\s*\([^)]*{expression_pattern}[^)]*\)\s*{statement_end_pattern}
        )
        | INSERT\s+(?:(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)|IGNORE)\s+)?INTO\b
        | DELETE\s+FROM\b
        | UPDATE\s+(?:{expression_pattern}|[^\s;]+)\s+SET\b
        | WITH\b[\s\S]{{0,4096}}\bAS\s*\(
    )
"""


_SQL_TEMPLATE_EXPRESSION_PATTERN = r"\{expr\}"
_SQL_SOURCE_EXPRESSION_PATTERN = r"\{[^{}\r\n]+\}"
_SQL_STATEMENT_PATTERN = _sql_statement_pattern(
    _SQL_TEMPLATE_EXPRESSION_PATTERN,
    include_contextual_select_expression=True,
    statement_end_pattern=r"(?:;|$)",
)
_SQL_SOURCE_STATEMENT_PATTERN = _sql_statement_pattern(
    _SQL_SOURCE_EXPRESSION_PATTERN,
    include_contextual_select_expression=False,
    statement_end_pattern=r"(?=\s*(?:'''|\"\"\"|'|\"))",
)
_SQL_STATEMENT_PREFIX_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS_PATTERN}{_SQL_STATEMENT_PATTERN}",
    re.IGNORECASE | re.VERBOSE,
)
_SQL_CONTEXTUAL_DYNAMIC_SELECT_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS_PATTERN}SELECT\s+"
    rf"(?=[\s\S]{{0,4096}}{_SQL_TEMPLATE_EXPRESSION_PATTERN})"
    rf"[\s\S]{{1,4096}}\s*;?\s*$",
    re.IGNORECASE | re.VERBOSE,
)
_SQL_STRONG_DYNAMIC_SELECT_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS_PATTERN}SELECT\s+(?:"
    rf"[\s\S]{{0,4096}}\bFROM\b"
    rf"|[A-Za-z_][A-Za-z0-9_$.]*\s*\([^)]*"
    rf"{_SQL_TEMPLATE_EXPRESSION_PATTERN}[^)]*\)\s*(?:;|$)"
    rf")",
    re.IGNORECASE | re.VERBOSE,
)
_SQL_CONTEXT_NAME_RE = re.compile(
    r"(?:^|_)(?:sql|query|statement|stmt)(?:_|$)",
    re.IGNORECASE,
)
_SQL_EXECUTION_CALL_NAMES = frozenset(
    {"execute", "executemany", "executescript", "fetch", "query", "raw"}
)
_PYTHON_SCOPE_DECLARATION_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<kind>async\s+def|def|class)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_PYTHON_FSTRING_SQL_FALLBACK_RE = re.compile(
    rf"""
    (?:^|[=(,:])\s*
    (?:[rub]*f[rub]*)
    (?:'''|\"\"\"|'|\")
    (?=[^\n]{{0,1000}}\{{[^{{}}\n]+\}})
    \s*{_SQL_LEADING_COMMENTS_PATTERN}{_SQL_SOURCE_STATEMENT_PATTERN}
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_PYTHON_CONCAT_SQL_FALLBACK_RE = re.compile(
    rf"""
    (?:^|[=(,:])\s*
    (?P<quote>'''|\"\"\"|'|\")
    \s*{_SQL_LEADING_COMMENTS_PATTERN}{_SQL_SOURCE_STATEMENT_PATTERN}
    [^\n]{{0,1000}}(?P=quote)\s*\+
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_PYTHON_FSTRING_CONTEXTUAL_SELECT_FALLBACK_RE = re.compile(
    rf"""
    ^[ \t]*
    (?P<target>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
    (?:\s*:\s*[^=\r\n]+)?\s*=\s*
    (?:[rub]*f[rub]*)
    (?P<quote>'''|\"\"\"|'|\")
    \s*{_SQL_LEADING_COMMENTS_PATTERN}SELECT\s+
    (?=[^\n]{{0,1000}}{_SQL_SOURCE_EXPRESSION_PATTERN})
    [^\n]{{1,1000}}?(?P=quote)
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_PYTHON_CONCAT_CONTEXTUAL_SELECT_FALLBACK_RE = re.compile(
    rf"""
    ^[ \t]*
    (?P<target>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
    (?:\s*:\s*[^=\r\n]+)?\s*=\s*
    (?P<quote>'''|\"\"\"|'|\")
    \s*{_SQL_LEADING_COMMENTS_PATTERN}SELECT\b
    [^\n]{{0,1000}}?(?P=quote)\s*\+
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_NON_CODE_TOKEN_TYPES = frozenset(
    {
        tokenize.COMMENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.NEWLINE,
        tokenize.NL,
    }
)


def is_test_file(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/").lower().lstrip("/")
    if "/tests/" in normalized or "/test/" in normalized or "__tests__" in normalized:
        return True
    return bool(re.search(r"\.(test|spec)\.[a-z0-9]+$|/test_[^/]+\.py$", normalized))


def index_to_line(content: str, idx: int) -> int:
    if idx <= 0:
        return 1
    return content.count("\n", 0, idx) + 1


def line_snippet(content: str, line_start: int, line_end: int) -> str:
    if not content:
        return ""
    lines = content.splitlines()
    start = max(line_start - 1, 0)
    end = min(line_end, len(lines))
    snippet = "\n".join(lines[start:end])
    return _truncate_snippet(snippet)


def blank_non_newlines(text: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in text)


def strip_js_comments_and_strings(content: str, comments_and_strings_re: re.Pattern[str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        return blank_non_newlines(match.group(0))

    return comments_and_strings_re.sub(_replace, content)


def python_eval_call_lines(content: str) -> set[int]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()

    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in {"eval", "exec"}:
                lines.add(int(getattr(node, "lineno", 1) or 1))
        elif isinstance(func, ast.Attribute):
            if func.attr in {"eval", "exec"}:
                lines.add(int(getattr(node, "lineno", 1) or 1))
    return lines


def python_interpolated_sql_lines(content: str) -> set[int]:
    """Return Python source lines that dynamically construct SQL statements.

    Parsed Python is authoritative. The bounded regex fallback exists only for
    otherwise-unparseable files and requires the string itself to begin with a
    SQL statement shape; ordinary prose containing words such as ``update`` is
    intentionally not enough.
    """

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _python_interpolated_sql_lines_from_source(content)

    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    sql_usage_names = _sql_usage_names_by_scope(tree, parents)
    constants = _module_string_constants(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        # Constants are trusted only in module-level expressions (a migration's DDL strings). Inside a
        # function or lambda, closures, nonlocal, exec and call-time globals() writes are out of reach
        # of a static binding count, so the old behaviour (every placeholder dynamic) stays.
        scoped = None
        if constants and isinstance(node, (ast.JoinedStr, ast.BinOp)) and _at_module_top_level(node, parents):
            scoped = constants
        template = _dynamic_string_template(node, parents, scoped)
        if (
            template is not None
            and _looks_like_sql_statement(template)
            and (
                not _select_requires_sql_context(template)
                or _has_sql_context(
                    node,
                    parents,
                    used_names=sql_usage_names.get(
                        _enclosing_scope(node, parents),
                        frozenset(),
                    ),
                )
            )
        ):
            lines.add(int(getattr(node, "lineno", 1) or 1))
    return lines


def _module_string_constants(tree: ast.AST) -> dict[str, str]:
    """Module-level names bound exactly once, at module level, to a string built only from literals.

    A migration that splices fixed table, function or trigger names into DDL through module
    constants is not dynamic SQL. A name counts only if NOTHING else in the file rebinds it
    (assignment, deletion, augmented assignment, loop/with/except/match target, import,
    def/class, function or lambda parameter, global or nonlocal), and its value is a str literal or an f-string/`+`
    concatenation of str literals and earlier such constants. Anything else (a call, an
    attribute, a parameter, os.environ, a format spec or a conversion) stays dynamic.
    """
    if any(_rebinds_names_dynamically(node) for node in ast.walk(tree)):
        return {}  # a wildcard import or a namespace write can rebind any module name
    bindings: dict[str, int] = {}

    def bind(name: str) -> None:
        bindings[name] = bindings.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        elif isinstance(node, ast.arg):
            bind(node.arg)  # a parameter (def or lambda, any kind) shadows the module name with caller data
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name)
                bind(name)  # another scope declared it rebindable: never a constant
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bind((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest)

    constants: dict[str, str] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for statement in body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = statement.targets[0], statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None and statement.simple:
            target, value = statement.target, statement.value
        else:
            continue
        if not isinstance(target, ast.Name) or bindings.get(target.id) != 1:
            continue
        resolved = _constant_string_value(value, constants)
        if resolved is not None:
            constants[target.id] = resolved
    return constants


# Names whose mere REFERENCE can lead to a run-time namespace write. A reference, not just a direct
# call, is enough: `g = globals; g()[...]`, `builtins.globals()[...]` and
# `from builtins import globals as g` are the same capability under another name.
_DYNAMIC_NAMESPACE_NAMES = frozenset({
    "globals", "locals", "vars", "exec", "eval", "compile", "setattr", "delattr", "getattr",
    "__import__", "__builtins__", "builtins", "importlib", "__dict__", "modules",
})


def _rebinds_names_dynamically(node: ast.AST) -> bool:
    """A wildcard import, or any reference to a capability that can write a namespace at run time."""
    if isinstance(node, ast.ImportFrom):
        return any(alias.name == "*" or alias.name in _DYNAMIC_NAMESPACE_NAMES for alias in node.names) or (
            (node.module or "").split(".")[0] in _DYNAMIC_NAMESPACE_NAMES
        )
    if isinstance(node, ast.Import):
        return any(alias.name.split(".")[0] in _DYNAMIC_NAMESPACE_NAMES for alias in node.names)
    if isinstance(node, ast.Name):
        return node.id in _DYNAMIC_NAMESPACE_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in _DYNAMIC_NAMESPACE_NAMES
    return False


def _at_module_top_level(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return False
        current = parents.get(current)
    return True


def _constant_string_value(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif (
                isinstance(value, ast.FormattedValue)
                and value.conversion == -1
                and value.format_spec is None
                and isinstance(value.value, ast.Name)
                and value.value.id in constants
            ):
                parts.append(constants[value.value.id])
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Flattened iteratively, like _concatenated_string_template: a 1,000-operand chain must not recurse.
        operands: list[ast.expr] = []
        pending: list[ast.expr] = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                pending.append(current.right)
                pending.append(current.left)
            else:
                operands.append(current)
        pieces: list[str] = []
        for operand in operands:
            fixed = _constant_string_value(operand, constants)
            if fixed is None:
                return None
            pieces.append(fixed)
        return "".join(pieces)
    return None


def _dynamic_string_template(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    constants: dict[str, str] | None = None,
) -> str | None:
    constants = constants or {}
    if isinstance(node, ast.JoinedStr):
        return _joined_string_template(node, constants)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parent = parents.get(node)
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
            return None
        return _concatenated_string_template(node, constants)
    return None


def _joined_string_template(node: ast.JoinedStr, constants: dict[str, str] | None = None) -> str | None:
    constants = constants or {}
    if not any(isinstance(value, ast.FormattedValue) for value in node.values):
        return None
    parts: list[str] = []
    dynamic = False
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            fixed = None
            if value.conversion == -1 and value.format_spec is None:
                fixed = _constant_string_value(value.value, constants)
            if fixed is None:
                dynamic = True
                parts.append("{expr}")
            else:
                parts.append(fixed)
    return "".join(parts) if dynamic else None


def _concatenated_string_template(node: ast.BinOp, constants: dict[str, str] | None = None) -> str | None:
    constants = constants or {}
    operands: list[ast.expr] = []
    pending: list[ast.expr] = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.append(current.right)
            pending.append(current.left)
        else:
            operands.append(current)

    has_string = False
    has_dynamic = False
    parts: list[str] = []
    for operand in operands:
        fixed = _constant_string_value(operand, constants)
        if fixed is not None:
            has_string = True
            parts.append(fixed)
        elif isinstance(operand, ast.JoinedStr):
            nested = _joined_string_template(operand, constants)
            if nested is None:
                return None
            has_string = True
            has_dynamic = True
            parts.append(nested)
        elif isinstance(operand, ast.Constant):
            return None
        else:
            has_dynamic = True
            parts.append("{expr}")
    if not has_string or not has_dynamic:
        return None
    return "".join(parts)


def _looks_like_sql_statement(template: str) -> bool:
    return bool(_SQL_STATEMENT_PREFIX_RE.search(template))


def _select_requires_sql_context(template: str) -> bool:
    return bool(
        _SQL_CONTEXTUAL_DYNAMIC_SELECT_RE.fullmatch(template)
        and not _SQL_STRONG_DYNAMIC_SELECT_RE.search(template)
    )


def _has_sql_context(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    *,
    used_names: frozenset[str] | set[str] = frozenset(),
    return_context_name: str | None = None,
) -> bool:
    """Require a direct SQL sink/binding for ambiguous dynamic SELECT text."""

    parent = parents.get(node)
    targets: list[ast.AST] = []
    if isinstance(parent, ast.Assign) and parent.value is node:
        targets.extend(parent.targets)
    elif (
        isinstance(parent, (ast.AnnAssign, ast.NamedExpr))
        and parent.value is node
    ):
        targets.append(parent.target)

    if targets:
        target_names = {
            name
            for target in targets
            for name in _target_reference_names(target)
        }
        if any(_is_sql_context_name(name.rsplit(".", 1)[-1]) for name in target_names):
            return True
        if target_names.intersection(used_names):
            return True

    call = parent if isinstance(parent, ast.Call) else None
    if isinstance(parent, ast.keyword):
        keyword_call = parents.get(parent)
        if isinstance(keyword_call, ast.Call) and parent.value is node:
            call = keyword_call
    if call is not None and _is_sql_execution_call(call):
        if node in call.args or any(
            keyword.value is node for keyword in call.keywords
        ):
            return True

    if isinstance(parent, ast.Return) and parent.value is node:
        if return_context_name is not None:
            return _is_sql_context_name(return_context_name)
        function = _enclosing_function(parent, parents)
        return function is not None and _is_sql_context_name(function.name)

    return False


def _target_reference_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Attribute):
        qualified = _qualified_name(target)
        return {qualified} if qualified is not None else {target.attr}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            name for element in target.elts for name in _target_reference_names(element)
        }
    return set()


def _is_sql_execution_call(call: ast.Call) -> bool:
    function_name = _qualified_name(call.func)
    return bool(
        function_name is not None
        and function_name.rsplit(".", 1)[-1].casefold()
        in _SQL_EXECUTION_CALL_NAMES
    )


def _sql_usage_names_by_scope(
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
) -> dict[ast.AST, frozenset[str]]:
    names_by_scope: dict[ast.AST, set[str]] = {}
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call) or not _is_sql_execution_call(candidate):
            continue
        scope = _enclosing_scope(candidate, parents)
        names = names_by_scope.setdefault(scope, set())
        for argument in [
            *candidate.args,
            *(keyword.value for keyword in candidate.keywords),
        ]:
            reference = _qualified_name(argument)
            if reference is not None:
                names.add(reference)
    return {scope: frozenset(names) for scope, names in names_by_scope.items()}


def _enclosing_scope(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> ast.AST:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(
            current,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
        ):
            return current
        current = parents.get(current)
    raise RuntimeError("Python AST node is detached from its module")


def _enclosing_function(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


def _is_sql_context_name(name: str) -> bool:
    return bool(_SQL_CONTEXT_NAME_RE.search(name))


def _recoverable_python_statements(content: str) -> list[_RecoveredPythonStatement]:
    """Parse valid one-line statements even when another line breaks the module."""

    recovered: list[_RecoveredPythonStatement] = []
    scope_stack: list[tuple[int, str, str, int]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indentation = len(line[: len(line) - len(line.lstrip())].expandtabs(8))
        while scope_stack and indentation <= scope_stack[-1][0]:
            scope_stack.pop()

        declaration = _PYTHON_SCOPE_DECLARATION_RE.match(line)
        if declaration is not None:
            kind = declaration.group("kind").casefold()
            scope_stack.append(
                (
                    indentation,
                    "function" if "def" in kind else "class",
                    declaration.group("name"),
                    line_number,
                )
            )
            continue

        try:
            tree = ast.parse(f"async def __recovered__():\n    {stripped}\n")
        except SyntaxError:
            continue
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        function_name = next(
            (
                name
                for _, kind, name, _ in reversed(scope_stack)
                if kind == "function"
            ),
            None,
        )
        recovered.append(
            _RecoveredPythonStatement(
                line_number=line_number,
                scope_key=tuple(entry[3] for entry in scope_stack),
                function_name=function_name,
                tree=tree,
                parents=parents,
            )
        )
    return recovered


def _python_interpolated_sql_lines_from_recovered_statements(
    content: str,
) -> set[int]:
    recovered = _recoverable_python_statements(content)
    usage_by_scope: dict[tuple[int, ...], set[str]] = {}
    for statement in recovered:
        used_names = usage_by_scope.setdefault(statement.scope_key, set())
        for candidate in ast.walk(statement.tree):
            if not isinstance(candidate, ast.Call) or not _is_sql_execution_call(
                candidate
            ):
                continue
            for argument in [
                *candidate.args,
                *(keyword.value for keyword in candidate.keywords),
            ]:
                reference = _qualified_name(argument)
                if reference is not None:
                    used_names.add(reference)

    lines: set[int] = set()
    for statement in recovered:
        used_names = usage_by_scope.get(statement.scope_key, set())
        for node in ast.walk(statement.tree):
            template = _dynamic_string_template(node, statement.parents)
            if (
                template is not None
                and _looks_like_sql_statement(template)
                and (
                    not _select_requires_sql_context(template)
                    or _has_sql_context(
                        node,
                        statement.parents,
                        used_names=used_names,
                        return_context_name=statement.function_name,
                    )
                )
            ):
                lines.add(statement.line_number)
    return lines


def _python_interpolated_sql_lines_from_source(content: str) -> set[int]:
    matches = [
        *_PYTHON_FSTRING_SQL_FALLBACK_RE.finditer(content),
        *_PYTHON_CONCAT_SQL_FALLBACK_RE.finditer(content),
    ]
    lines = {index_to_line(content, match.start()) for match in matches}
    lines.update(
        index_to_line(content, match.start())
        for pattern in (
            _PYTHON_FSTRING_CONTEXTUAL_SELECT_FALLBACK_RE,
            _PYTHON_CONCAT_CONTEXTUAL_SELECT_FALLBACK_RE,
        )
        for match in pattern.finditer(content)
        if _is_sql_context_name(match.group("target").rsplit(".", 1)[-1])
    )
    lines.update(_python_interpolated_sql_lines_from_recovered_statements(content))
    return lines


def python_httpx_calls(content: str) -> list[PythonHttpxCall]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _python_httpx_calls_from_tokens(content)

    calls: list[PythonHttpxCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = _qualified_name(node.func)
        canonical_name = (
            _HTTPX_FUNCTION_NAMES_BY_CASEFOLD.get(function_name.casefold())
            if function_name is not None
            else None
        )
        if canonical_name is None:
            continue
        line_start = int(getattr(node, "lineno", 1) or 1)
        calls.append(
            PythonHttpxCall(
                function_name=canonical_name,
                line_start=line_start,
                line_end=int(getattr(node, "end_lineno", line_start) or line_start),
                has_timeout=any(keyword.arg == "timeout" for keyword in node.keywords),
            )
        )

    return sorted(calls, key=lambda call: (call.line_start, call.line_end))


def _qualified_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _python_httpx_calls_from_tokens(content: str) -> list[PythonHttpxCall]:
    tokens: list[tokenize.TokenInfo] = []
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)
    try:
        for token in token_stream:
            if token.type not in _NON_CODE_TOKEN_TYPES:
                tokens.append(token)
    except (SyntaxError, tokenize.TokenError):
        # Tokenization is still useful up to an unrelated syntax error.
        pass

    calls: list[PythonHttpxCall] = []
    for index in range(len(tokens) - 3):
        if not (
            tokens[index].type == tokenize.NAME
            and tokens[index].string.casefold() == "httpx"
            and tokens[index + 1].type == tokenize.OP
            and tokens[index + 1].string == "."
            and tokens[index + 2].type == tokenize.NAME
            and tokens[index + 3].type == tokenize.OP
            and tokens[index + 3].string == "("
        ):
            continue
        canonical_name = _HTTPX_FUNCTION_NAMES_BY_CASEFOLD.get(
            f"httpx.{tokens[index + 2].string}".casefold()
        )
        if canonical_name is None:
            continue
        call = _balanced_httpx_call(
            tokens,
            function_name=canonical_name,
            function_index=index + 2,
            open_paren_index=index + 3,
        )
        if call is not None:
            calls.append(call)

    return sorted(calls, key=lambda call: (call.line_start, call.line_end))


def _balanced_httpx_call(
    tokens: list[tokenize.TokenInfo],
    *,
    function_name: str,
    function_index: int,
    open_paren_index: int,
) -> PythonHttpxCall | None:
    opening_for_closing = {")": "(", "]": "[", "}": "{"}
    opening_tokens = frozenset(opening_for_closing.values())
    stack: list[str] = []
    has_timeout = False
    scan_limit = min(
        len(tokens),
        open_paren_index + _MAX_FALLBACK_CALL_TOKENS + 1,
    )

    for index in range(open_paren_index, scan_limit):
        token = tokens[index]
        if token.type == tokenize.OP and token.string in opening_tokens:
            stack.append(token.string)
            continue
        if token.type == tokenize.OP and token.string in opening_for_closing:
            if not stack or stack[-1] != opening_for_closing[token.string]:
                return None
            stack.pop()
            if not stack:
                return PythonHttpxCall(
                    function_name=function_name,
                    line_start=tokens[function_index - 2].start[0],
                    line_end=token.end[0],
                    has_timeout=has_timeout,
                )
            continue
        if (
            len(stack) == 1
            and token.type == tokenize.NAME
            and token.string == "timeout"
            and index + 1 < scan_limit
            and tokens[index + 1].type == tokenize.OP
            and tokens[index + 1].string == "="
            and (
                index == open_paren_index + 1
                or (
                    tokens[index - 1].type == tokenize.OP
                    and tokens[index - 1].string == ","
                )
            )
        ):
            has_timeout = True

    return None
