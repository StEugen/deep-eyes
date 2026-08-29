"""Matcher logic for template engine."""
import ast
import operator
import regex as safe_regex
from typing import Any, Dict, List, Tuple


_DSL_MAX_LENGTH = 500
_DSL_MAX_NODES = 100
_REGEX_MAX_PATTERN_LENGTH = 2_000
_REGEX_MAX_TEXT_LENGTH = 1_000_000
_REGEX_TIMEOUT_SECONDS = 0.1
_DSL_NAMES = {"status_code", "body", "True", "False"}
_DSL_COMPARE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: operator.contains(right, left),
    ast.NotIn: lambda left, right: not operator.contains(right, left),
}
_DSL_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}


def _parse_dsl_expression(expression: str) -> ast.Expression:
    """Parse a small expression language without executing Python code."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("DSL expression must be a non-empty string")
    if len(expression) > _DSL_MAX_LENGTH:
        raise ValueError("DSL expression is too long")
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError) as exc:
        raise ValueError("invalid DSL expression") from exc
    if sum(1 for _ in ast.walk(tree)) > _DSL_MAX_NODES:
        raise ValueError("DSL expression is too complex")
    return tree


def validate_dsl_expression(expression: str) -> None:
    """Validate that an expression contains only the supported DSL grammar."""
    tree = _parse_dsl_expression(expression)
    _evaluate_dsl_node(tree.body, {"status_code": 0, "body": ""}, validate_only=True)


def evaluate_dsl_expression(expression: str, status_code: int, body: str) -> Any:
    """Evaluate the allowlisted template DSL against response primitives."""
    tree = _parse_dsl_expression(expression)
    return _evaluate_dsl_node(
        tree.body,
        {"status_code": status_code, "body": body},
        validate_only=False,
    )


def _evaluate_dsl_node(node: ast.AST, values: Dict[str, Any], validate_only: bool) -> Any:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float, bool, type(None))):
            return node.value
        raise ValueError("unsupported DSL constant")

    if isinstance(node, ast.Name):
        if node.id not in _DSL_NAMES:
            raise ValueError(f"unsupported DSL name: {node.id}")
        if node.id == "True":
            return True
        if node.id == "False":
            return False
        return values[node.id]

    if isinstance(node, (ast.List, ast.Tuple)):
        items = [_evaluate_dsl_node(item, values, validate_only) for item in node.elts]
        return items if isinstance(node, ast.List) else tuple(items)

    if isinstance(node, ast.Call):
        if (
            not isinstance(node.func, ast.Name)
            or node.func.id != "len"
            or len(node.args) != 1
            or node.keywords
        ):
            raise ValueError("only len(value) is supported in DSL calls")
        value = _evaluate_dsl_node(node.args[0], values, validate_only)
        return 0 if validate_only else len(value)

    if isinstance(node, ast.UnaryOp):
        operand = _evaluate_dsl_node(node.operand, values, validate_only)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub) and isinstance(operand, (int, float)):
            return -operand
        if isinstance(node.op, ast.UAdd) and isinstance(operand, (int, float)):
            return +operand
        raise ValueError("unsupported DSL unary operator")

    if isinstance(node, ast.BoolOp):
        results = [_evaluate_dsl_node(item, values, validate_only) for item in node.values]
        if isinstance(node.op, ast.And):
            return all(results)
        if isinstance(node.op, ast.Or):
            return any(results)
        raise ValueError("unsupported DSL boolean operator")

    if isinstance(node, ast.BinOp):
        operation = _DSL_BINARY_OPERATORS.get(type(node.op))
        if operation is None:
            raise ValueError("unsupported DSL binary operator")
        left = _evaluate_dsl_node(node.left, values, validate_only)
        right = _evaluate_dsl_node(node.right, values, validate_only)
        if validate_only:
            return 0
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            raise ValueError("DSL arithmetic requires numeric operands")
        return operation(left, right)

    if isinstance(node, ast.Compare):
        left = _evaluate_dsl_node(node.left, values, validate_only)
        for op_node, comparator in zip(node.ops, node.comparators):
            right = _evaluate_dsl_node(comparator, values, validate_only)
            operation = _DSL_COMPARE_OPERATORS.get(type(op_node))
            if operation is None:
                raise ValueError("unsupported DSL comparison operator")
            if not validate_only and not operation(left, right):
                return False
            left = right
        return True

    raise ValueError(f"unsupported DSL syntax: {type(node).__name__}")


def _get_part(response, part: str) -> str:
    """Extract response part as string."""
    if part == "header":
        headers = getattr(response, "headers", {})
        if hasattr(headers, "items"):
            return "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        return str(headers)
    if part == "body":
        return getattr(response, "text", "") or ""
    if part in ("response", "all"):
        body = getattr(response, "text", "") or ""
        headers = getattr(response, "headers", {})
        if hasattr(headers, "items"):
            header_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        else:
            header_str = str(headers)
        return f"{header_str}\r\n\r\n{body}"
    return ""


def match_status(response, matcher: Dict) -> bool:
    status = getattr(response, "status_code", None)
    expected = matcher.get("status", [])
    return status in expected


def match_word(response, matcher: Dict) -> bool:
    part = matcher.get("part", "body")
    text = _get_part(response, part)
    case_insensitive = matcher.get("case-insensitive", False)
    if case_insensitive:
        text = text.lower()
    words = matcher.get("words", [])
    condition = matcher.get("condition", "or").lower()

    matches = []
    for w in words:
        target = w.lower() if case_insensitive else w
        matches.append(target in text)

    if condition == "and":
        return all(matches) if matches else False
    return any(matches)


def match_regex(response, matcher: Dict) -> bool:
    part = matcher.get("part", "body")
    text = _get_part(response, part)[:_REGEX_MAX_TEXT_LENGTH]
    patterns = matcher.get("regex", [])
    condition = matcher.get("condition", "or").lower()

    matches = []
    for pat in patterns:
        if not isinstance(pat, str) or len(pat) > _REGEX_MAX_PATTERN_LENGTH:
            matches.append(False)
            continue
        try:
            matches.append(
                bool(safe_regex.search(pat, text, timeout=_REGEX_TIMEOUT_SECONDS))
            )
        except (safe_regex.error, TimeoutError):
            matches.append(False)

    if condition == "and":
        return all(matches) if matches else False
    return any(matches)


def match_size(response, matcher: Dict) -> bool:
    text = getattr(response, "text", "") or ""
    body_size = len(text)
    sizes = matcher.get("size", [])
    return body_size in sizes


def match_dsl(response, matcher: Dict) -> bool:
    """Minimal DSL: status_code, len(body), simple comparisons."""
    text = getattr(response, "text", "") or ""
    status_code = getattr(response, "status_code", 0)
    expressions = matcher.get("dsl", [])
    condition = matcher.get("condition", "and").lower()
    results = []
    for expr in expressions:
        try:
            results.append(bool(evaluate_dsl_expression(str(expr), status_code, text)))
        except (TypeError, ValueError, ZeroDivisionError):
            results.append(False)
    if condition == "or":
        return any(results)
    return all(results) if results else False


_MATCHERS = {
    "status": match_status,
    "word": match_word,
    "regex": match_regex,
    "size": match_size,
    "dsl": match_dsl,
}


def evaluate_matchers(response, matchers: List[Dict], condition: str = "or") -> Tuple[bool, List[Dict]]:
    """Run all matchers, combine via condition. Returns (overall, individual results)."""
    if not matchers:
        return False, []

    results = []
    for m in matchers:
        mtype = m.get("type")
        fn = _MATCHERS.get(mtype)
        if fn is None:
            results.append({"type": mtype, "matched": False, "error": "unknown matcher"})
            continue
        try:
            matched = fn(response, m)
        except Exception:
            matched = False
        results.append({"type": mtype, "matched": matched})

    cond = (condition or "or").lower()
    overall_results = [r["matched"] for r in results]
    if cond == "and":
        overall = all(overall_results) if overall_results else False
    else:
        overall = any(overall_results)
    return overall, results


def run_extractors(response, extractors: List[Dict]) -> Dict[str, List[str]]:
    """Run extractors. Returns {name: [matched values]}."""
    out: Dict[str, List[str]] = {}
    for i, ext in enumerate(extractors or []):
        ext_type = ext.get("type")
        name = ext.get("name", f"extracted_{i}")
        part = ext.get("part", "body")
        text = _get_part(response, part)[:_REGEX_MAX_TEXT_LENGTH]
        values: List[str] = []
        if ext_type == "regex":
            patterns = ext.get("regex", [])
            group = int(ext.get("group", 0))
            for pat in patterns:
                if not isinstance(pat, str) or len(pat) > _REGEX_MAX_PATTERN_LENGTH:
                    continue
                try:
                    for m in safe_regex.finditer(
                        pat,
                        text,
                        timeout=_REGEX_TIMEOUT_SECONDS,
                    ):
                        try:
                            values.append(m.group(group))
                        except (IndexError, TypeError):
                            values.append(m.group(0))
                except (safe_regex.error, TimeoutError):
                    continue
        out[name] = values
    return out
