"""AST Entry-Point-to-Sink Taint & Call-Graph Reachability Scanner (`secposture/reachability_ast.py`).

Parses Python service code with `ast`, discovers HTTP/Lambda entrypoints, constructs the
intra-module call graph, propagates untrusted parameter taint across helper calls, detects
dangerous sinks and hardcoded secrets, and separates REACHABLE_EXPLOITABLE exposures from
UNREACHABLE_DEAD_CODE helpers.
"""
from __future__ import annotations

import ast
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

ENTRYPOINT_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "api_endpoint",
    "webhook_handler",
}

ENTRYPOINT_NAMES = {
    "lambda_handler",
    "handler",
    "handle_sqs_event",
    "handle_http_request",
}

SECRET_NAME_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|HMAC)", re.IGNORECASE)
HIGH_ENTROPY_LITERAL_RE = re.compile(r"^[A-Za-z0-9_\-+/=]{18,}$")
SAFE_TEST_PLACEHOLDERS = {
    "dev-test-hmac-key",
    "ephemeral-dev-verify-key",
    "unit-test-hmac-secret-key-01",
    "",
}


def _decorator_label(dec: ast.expr) -> Optional[str]:
    if isinstance(dec, ast.Call):
        func = dec.func
        name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if name in ENTRYPOINT_DECORATORS:
            route_path = "/"
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                route_path = dec.args[0].value
            return f"@{name}({route_path})"
    elif isinstance(dec, ast.Name) and dec.id in ENTRYPOINT_DECORATORS:
        return f"@{dec.id}"
    elif isinstance(dec, ast.Attribute) and dec.attr in ENTRYPOINT_DECORATORS:
        return f"@{dec.attr}"
    return None


def _call_qualname(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        parts: List[str] = [fn.attr]
        cur = fn.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _names_in_expr(node: Optional[ast.AST]) -> Set[str]:
    if node is None:
        return set()
    return {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}


def _is_dynamic_sql_expr(expr: ast.AST) -> Tuple[bool, str]:
    """Check whether a SQL query argument uses string interpolation/concatenation rather than constant SQL."""
    if isinstance(expr, ast.JoinedStr):
        return True, "f-string interpolation in SQL query"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return True, "string concatenation (+) in SQL query"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return True, "percent (%) formatting in SQL query"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True, ".format() interpolation in SQL query"
    return False, ""


def _kwarg_bool(call: ast.Call, kw_name: str) -> Optional[bool]:
    for kw in call.keywords:
        if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
            return kw.value.value
    return None


class ReachabilityASTScanner:
    """Deterministic AST Call-Graph + Intra/Inter-Procedural Taint Scanner."""

    def scan_source(self, source_code: str, filename: str = "service.py") -> Dict[str, Any]:
        t0 = time.perf_counter()
        tree = ast.parse(source_code, filename=filename)
        lines = source_code.splitlines()

        functions: Dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        entrypoints: Dict[str, Dict[str, Any]] = {}
        module_secrets: Dict[str, Dict[str, Any]] = {}

        # Pass 1: Collect module-level hardcoded secrets and function definitions
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and SECRET_NAME_RE.search(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value.strip()
                            if val not in SAFE_TEST_PLACEHOLDERS and HIGH_ENTROPY_LITERAL_RE.match(val):
                                module_secrets[target.id] = {
                                    "symbol": target.id,
                                    "lineno": node.lineno,
                                    "snippet": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                }
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name] = node
                dec_labels = [_decorator_label(d) for d in node.decorator_list]
                dec_labels = [d for d in dec_labels if d]
                if dec_labels:
                    entrypoints[node.name] = {
                        "function": node.name,
                        "kind": "HTTP_ROUTE",
                        "trigger": dec_labels[0],
                        "lineno": node.lineno,
                    }
                elif node.name in ENTRYPOINT_NAMES or node.name.endswith("_endpoint"):
                    entrypoints[node.name] = {
                        "function": node.name,
                        "kind": "LAMBDA_OR_HANDLER",
                        "trigger": f"handler:{node.name}",
                        "lineno": node.lineno,
                    }

        # Pass 2: Build directed call graph & function-level variable taint maps
        call_graph: Dict[str, List[Dict[str, Any]]] = {fn_name: [] for fn_name in functions}
        func_local_defs: Dict[str, Dict[str, ast.AST]] = {}
        func_tainted_vars: Dict[str, Set[str]] = {}
        func_has_ssrf_guard: Dict[str, bool] = {}

        for fn_name, fn_node in functions.items():
            # Seed tainted variables with function parameters (excluding db connections & context)
            params = [
                arg.arg
                for arg in fn_node.args.args
                if arg.arg not in ("self", "cls", "conn", "cursor", "context", "opener")
            ]
            tainted: Set[str] = set(params)
            local_defs: Dict[str, ast.AST] = {}
            has_ssrf_guard = False

            # Propagate taint across local assignments in source order
            for stmt in ast.walk(fn_node):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    lhs = stmt.targets[0].id
                    local_defs[lhs] = stmt.value
                    rhs_names = _names_in_expr(stmt.value)
                    if rhs_names & tainted:
                        tainted.add(lhs)
                elif isinstance(stmt, ast.Call):
                    qname = _call_qualname(stmt)
                    if qname in ("_validate_https_allowlist", "validate_https_allowlist"):
                        has_ssrf_guard = True
                    callee_simple = qname.split(".")[-1]
                    if callee_simple in functions and callee_simple != fn_name:
                        arg_names = set()
                        for a in stmt.args:
                            arg_names |= _names_in_expr(a)
                        for kw in stmt.keywords:
                            arg_names |= _names_in_expr(kw.value)
                        call_graph[fn_name].append(
                            {
                                "callee": callee_simple,
                                "lineno": stmt.lineno,
                                "passes_tainted_input": bool(arg_names & tainted),
                                "tainted_vars": sorted(arg_names & tainted),
                            }
                        )

            func_local_defs[fn_name] = local_defs
            func_tainted_vars[fn_name] = tainted
            func_has_ssrf_guard[fn_name] = has_ssrf_guard

        # Pass 3: Compute shortest call-graph paths from any entrypoint to every reachable function
        shortest_paths: Dict[str, List[str]] = {}
        entry_for_func: Dict[str, str] = {}
        queue: deque[str] = deque()

        for ep_name, ep_meta in entrypoints.items():
            shortest_paths[ep_name] = [f"{ep_meta['trigger']} ({ep_name}:L{ep_meta['lineno']})"]
            entry_for_func[ep_name] = ep_name
            queue.append(ep_name)

        while queue:
            cur = queue.popleft()
            for edge in call_graph.get(cur, []):
                nxt = edge["callee"]
                if nxt not in shortest_paths:
                    callee_node = functions[nxt]
                    shortest_paths[nxt] = shortest_paths[cur] + [f"{nxt}:L{callee_node.lineno} (called at L{edge['lineno']})"]
                    entry_for_func[nxt] = entry_for_func[cur]
                    queue.append(nxt)

        # Pass 4: Inspect dangerous sinks inside functions + hardcoded secret references
        raw_findings: List[Dict[str, Any]] = []
        reported_secrets: Set[str] = set()

        for fn_name, fn_node in functions.items():
            local_defs = func_local_defs[fn_name]
            tainted = func_tainted_vars[fn_name]
            is_reachable = fn_name in shortest_paths
            call_chain = shortest_paths.get(fn_name, [f"{fn_name}:L{fn_node.lineno} (UNREFERENCED DEAD CODE)"])

            # Check references to module-level hardcoded secrets
            for sub in ast.walk(fn_node):
                if isinstance(sub, ast.Name) and sub.id in module_secrets:
                    sec = module_secrets[sub.id]
                    dedup_key = f"{sec['symbol']}:{is_reachable}"
                    if dedup_key not in reported_secrets:
                        reported_secrets.add(dedup_key)
                        raw_findings.append(
                            self._make_finding(
                                rule_id="SEC-AST-SECRET-05",
                                cwe="CWE-798",
                                severity="HIGH",
                                category="Hardcoded Signing / API Secret",
                                filename=filename,
                                lineno=sec["lineno"],
                                function_name=fn_name,
                                sink_expr=sec["symbol"],
                                snippet=sec["snippet"],
                                reachable=is_reachable,
                                entrypoint=entry_for_func.get(fn_name),
                                call_chain=call_chain + [f"uses {sec['symbol']} (defined L{sec['lineno']})"],
                                taint_summary=f"Constant secret literal '{sec['symbol']}' embedded in source and read by {fn_name}()",
                                remediation_hint="Load secret from os.environ / AWS Secrets Manager instead of hardcoding literal.",
                            )
                        )

            # Check AST Call sinks
            for sub in ast.walk(fn_node):
                if not isinstance(sub, ast.Call):
                    continue
                qname = _call_qualname(sub)
                snippet = lines[sub.lineno - 1].strip() if sub.lineno <= len(lines) else ""

                # 1. SQL Injection: *.execute(sql) without parameterized query
                if qname.endswith(".execute") and sub.args:
                    first_arg = sub.args[0]
                    resolved_expr = local_defs.get(first_arg.id, first_arg) if isinstance(first_arg, ast.Name) else first_arg
                    is_dyn, dyn_reason = _is_dynamic_sql_expr(resolved_expr)
                    if is_dyn:
                        expr_vars = sorted(_names_in_expr(resolved_expr) & tainted)
                        raw_findings.append(
                            self._make_finding(
                                rule_id="SEC-AST-SQLI-01",
                                cwe="CWE-89",
                                severity="CRITICAL",
                                category="SQL Injection (Unparameterized Query)",
                                filename=filename,
                                lineno=sub.lineno,
                                function_name=fn_name,
                                sink_expr=qname,
                                snippet=snippet,
                                reachable=is_reachable,
                                entrypoint=entry_for_func.get(fn_name),
                                call_chain=call_chain + [f"{qname}() at L{sub.lineno}"],
                                taint_summary=f"{dyn_reason}; tainted inputs: {', '.join(expr_vars) or 'untrusted arg'}",
                                remediation_hint="Replace string interpolation with '?' parameter placeholders and a tuple of bound values.",
                            )
                        )

                # 2. Command Injection: subprocess.*(..., shell=True) or os.system(...)
                elif qname in ("subprocess.run", "subprocess.Popen", "subprocess.call") or qname == "os.system":
                    is_os_sys = qname == "os.system"
                    shell_true = _kwarg_bool(sub, "shell") is True
                    if is_os_sys or shell_true:
                        cmd_arg = sub.args[0] if sub.args else None
                        cmd_vars = sorted(_names_in_expr(cmd_arg) & tainted)
                        raw_findings.append(
                            self._make_finding(
                                rule_id="SEC-AST-CMDI-02",
                                cwe="CWE-78",
                                severity="CRITICAL",
                                category="OS Command Injection (Shell Execution)",
                                filename=filename,
                                lineno=sub.lineno,
                                function_name=fn_name,
                                sink_expr=qname,
                                snippet=snippet,
                                reachable=is_reachable,
                                entrypoint=entry_for_func.get(fn_name),
                                call_chain=call_chain + [f"{qname}(shell=True) at L{sub.lineno}"],
                                taint_summary=f"Shell interpreter spawned with tainted args: {', '.join(cmd_vars) or 'dynamic command'}",
                                remediation_hint="Pass an explicit argv list with shell=False and reject path/argument metacharacters.",
                            )
                        )

                # 3. SSRF: urllib.request.urlopen / requests.get without allowlist guard
                elif qname in ("urllib.request.urlopen", "urlopen", "requests.get", "requests.post"):
                    if not func_has_ssrf_guard.get(fn_name, False):
                        url_arg = sub.args[0] if sub.args else None
                        url_vars = sorted(_names_in_expr(url_arg) & tainted)
                        if url_vars or isinstance(url_arg, ast.Name):
                            raw_findings.append(
                                self._make_finding(
                                    rule_id="SEC-AST-SSRF-03",
                                    cwe="CWE-918",
                                    severity="HIGH",
                                    category="Server-Side Request Forgery (Unvalidated URL)",
                                    filename=filename,
                                    lineno=sub.lineno,
                                    function_name=fn_name,
                                    sink_expr=qname,
                                    snippet=snippet,
                                    reachable=is_reachable,
                                     entrypoint=entry_for_func.get(fn_name),
                                    call_chain=call_chain + [f"{qname}() at L{sub.lineno}"],
                                    taint_summary=f"Outbound URL sink called without HTTPS host allowlist or link-local IP block ({', '.join(url_vars)})",
                                    remediation_hint="Validate HTTPS scheme, block private/link-local/IMDS IPs, and check hostname against ALLOWED_PARTNER_HOSTS.",
                                )
                            )

                # 4. Insecure Deserialization: pickle.loads / pickle.load / unsafe yaml.load
                elif qname in ("pickle.loads", "pickle.load", "marshal.loads"):
                    arg0 = sub.args[0] if sub.args else None
                    p_vars = sorted(_names_in_expr(arg0) & tainted)
                    raw_findings.append(
                        self._make_finding(
                            rule_id="SEC-AST-DESER-04",
                            cwe="CWE-502",
                            severity="CRITICAL",
                            category="Arbitrary Code Execution via pickle.loads",
                            filename=filename,
                            lineno=sub.lineno,
                            function_name=fn_name,
                            sink_expr=qname,
                            snippet=snippet,
                            reachable=is_reachable,
                            entrypoint=entry_for_func.get(fn_name),
                            call_chain=call_chain + [f"{qname}() at L{sub.lineno}"],
                            taint_summary=f"Untrusted byte stream ({', '.join(p_vars) or 'payload'}) passed to pickle deserializer",
                            remediation_hint="Replace pickle.loads() with json.loads() and validate decoded schema.",
                        )
                    )

        # Unreferenced module-level secrets if never used in any reachable function
        for sym, sec in module_secrets.items():
            if f"{sym}:True" not in reported_secrets and f"{sym}:False" not in reported_secrets:
                raw_findings.append(
                    self._make_finding(
                        rule_id="SEC-AST-SECRET-05",
                        cwe="CWE-798",
                        severity="MEDIUM",
                        category="Unused Hardcoded Secret Constant",
                        filename=filename,
                        lineno=sec["lineno"],
                        function_name="<module>",
                        sink_expr=sym,
                        snippet=sec["snippet"],
                        reachable=False,
                        entrypoint=None,
                        call_chain=[f"<module>:L{sec['lineno']} (UNREFERENCED CONSTANT)"],
                        taint_summary=f"Hardcoded secret '{sym}' defined at module scope with zero reachable callers",
                        remediation_hint="Remove unused secret literal and load credentials from environment variables.",
                    )
                )

        reachable_findings = [f for f in raw_findings if f["reachability"] == "REACHABLE_EXPLOITABLE"]
        unreachable_findings = [f for f in raw_findings if f["reachability"] == "UNREACHABLE_DEAD_CODE"]
        total_raw = len(raw_findings)
        noise_pct = round((len(unreachable_findings) / total_raw) * 100.0, 1) if total_raw > 0 else 0.0

        # Service security posture score (100 when 0 reachable vulns; penalized strongly per reachable CRITICAL/HIGH, lightly for dead code hygiene)
        penalty = sum(28 if f["severity"] == "CRITICAL" else 20 for f in reachable_findings) + (len(unreachable_findings) * 2)
        posture_score = max(5, 100 - penalty) if reachable_findings else max(92, 100 - (len(unreachable_findings) * 2))

        scan_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return {
            "filename": filename,
            "scan_ms": scan_ms,
            "entrypoints": list(entrypoints.values()),
            "total_functions": len(functions),
            "reachable_functions": sorted(shortest_paths.keys()),
            "unreachable_functions": sorted(set(functions.keys()) - set(shortest_paths.keys())),
            "call_graph": call_graph,
            "total_raw_findings": total_raw,
            "reachable_count": len(reachable_findings),
            "unreachable_count": len(unreachable_findings),
            "alert_noise_reduction_pct": noise_pct,
            "posture_score": posture_score,
            "posture_status": "BLOCK_LAUNCH" if reachable_findings else "LAUNCH_READY",
            "reachable_findings": reachable_findings,
            "unreachable_findings": unreachable_findings,
            "all_findings": raw_findings,
        }

    @staticmethod
    def _make_finding(
        rule_id: str,
        cwe: str,
        severity: str,
        category: str,
        filename: str,
        lineno: int,
        function_name: str,
        sink_expr: str,
        snippet: str,
        reachable: bool,
        entrypoint: Optional[str],
        call_chain: List[str],
        taint_summary: str,
        remediation_hint: str,
    ) -> Dict[str, Any]:
        return {
            "finding_id": f"{rule_id}:{filename}:L{lineno}",
            "rule_id": rule_id,
            "cwe": cwe,
            "severity": severity if reachable else "LOW_DEAD_CODE",
            "raw_severity": severity,
            "category": category,
            "location": f"{filename}:{lineno}",
            "lineno": lineno,
            "function_name": function_name,
            "sink_expr": sink_expr,
            "snippet": snippet,
            "reachability": "REACHABLE_EXPLOITABLE" if reachable else "UNREACHABLE_DEAD_CODE",
            "entrypoint": entrypoint,
            "call_chain": call_chain,
            "taint_summary": taint_summary,
            "remediation_hint": remediation_hint,
        }


def scan_python_reachability(source_code: str, filename: str = "service.py") -> Dict[str, Any]:
    return ReachabilityASTScanner().scan_source(source_code=source_code, filename=filename)
