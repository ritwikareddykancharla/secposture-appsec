"""Closed-Loop Vulnerability Auto-Patcher & Unit-Test Verifier (`secposture/autopatch_loop.py`).

Synthesizes minimal, targeted security patches for reachable AST vulnerabilities:
  - SEC-AST-SQLI-01  -> Parameterized '?' SQL queries with bound parameter tuples
  - SEC-AST-CMDI-02  -> subprocess.run(argv_list, shell=False) + strict argument metacharacter guard
  - SEC-AST-SSRF-03  -> _validate_https_allowlist() blocking HTTP, loopback, RFC1918 & 169.254.169.254 IMDS
  - SEC-AST-DESER-04 -> json.loads() replacing unsafe pickle.loads()
  - SEC-AST-SECRET-05 -> os.environ.get() replacing hardcoded secret literals

Writes the patched service and unit tests into an isolated `/tmp` directory, re-runs the AST
reachability scanner (`0` reachable vulnerabilities required), and executes `python3 -m unittest`
in `shell=False` subprocess isolation (`100%` unit tests required to pass) before marking a patch
`VERIFIED_READY_FOR_CR`.
"""
from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .reachability_ast import scan_python_reachability
from .sample_services import SERVICE_REPOS

SSRF_HELPER_BLOCK = '''
def _validate_https_allowlist(target_url: str, allowed_hosts=()) -> str:
    import ipaddress
    from urllib.parse import urlparse
    parsed = urlparse(str(target_url).strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Blocked non-HTTPS or malformed outbound URL: {target_url}")
    host = parsed.hostname.lower()
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise ValueError(f"Blocked private/link-local SSRF target IP: {host}")
    except ValueError as exc:
        if "Blocked" in str(exc):
            raise
    if allowed_hosts and host not in {h.lower() for h in allowed_hosts}:
        raise ValueError(f"Outbound host '{host}' is not in ALLOWED_PARTNER_HOSTS")
    return target_url
'''

CLI_GUARD_HELPER_BLOCK = '''
def _validate_safe_cli_arg(raw_arg: str) -> str:
    val = str(raw_arg).strip()
    if not val or any(ch in val for ch in (";", "|", "&", "$", "`", "\\n", "\\r", ">", "<")):
        raise ValueError(f"Blocked unsafe shell metacharacter in CLI argument: {raw_arg}")
    return val
'''


def _extract_function_ranges(source_code: str) -> Dict[str, Tuple[int, int]]:
    tree = ast.parse(source_code)
    ranges: Dict[str, Tuple[int, int]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.end_lineno:
            ranges[node.name] = (node.lineno, node.end_lineno)
    return ranges


def _patch_sql_lines_in_function(fn_lines: List[str]) -> Tuple[List[str], List[str]]:
    """Rewrite f-string, .format(), '+' concat, and '%' SQL queries inside a reachable function to '?' bindings."""
    patched: List[str] = []
    notes: List[str] = []
    pending_sql_var: Optional[Tuple[str, List[str]]] = None

    # Pattern 1: var = f"SELECT ... '{a}' ... '{b}'"
    fstr_assign_re = re.compile(r'^(\s*)(\w+)\s*=\s*f(["\'])(SELECT|INSERT|UPDATE|DELETE)(.+)\3\s*$', re.IGNORECASE)
    # Pattern 2: var = "SELECT ... '{}'".format(a, b)
    fmt_assign_re = re.compile(r'^(\s*)(\w+)\s*=\s*(["\'])(SELECT|INSERT|UPDATE|DELETE)(.+)\3\.format\((.+)\)\s*$', re.IGNORECASE)
    # Pattern 3: var = "SELECT ... '" + a + "'"
    concat_assign_re = re.compile(
        r'^(\s*)(\w+)\s*=\s*"([^"]*?)\'"\s*\+\s*(\w+)\s*\+\s*"\'([^"]*)"\s*$', re.IGNORECASE
    )

    for line in fn_lines:
        m_fstr = fstr_assign_re.match(line)
        if m_fstr:
            indent, var_name, quote, verb, rest = m_fstr.groups()
            vars_found = re.findall(r"\{([^}]+)\}", rest)
            clean_rest = re.sub(r"'\{[^}]+\}'|\{[^}]+\}", "?", rest)
            patched.append(f'{indent}{var_name} = "{verb}{clean_rest}"')
            pending_sql_var = (var_name, [v.strip() for v in vars_found])
            notes.append(f"Converted f-string SQL in '{var_name}' to '?' placeholders ({len(vars_found)} bound params)")
            continue

        m_fmt = fmt_assign_re.match(line)
        if m_fmt:
            indent, var_name, quote, verb, rest, fmt_args = m_fmt.groups()
            args_list = [a.strip() for a in fmt_args.split(",") if a.strip()]
            clean_rest = re.sub(r"'\{\}'|\{\}", "?", rest)
            patched.append(f'{indent}{var_name} = "{verb}{clean_rest}"')
            pending_sql_var = (var_name, args_list)
            notes.append(f"Converted .format() SQL in '{var_name}' to '?' placeholders")
            continue

        m_concat = concat_assign_re.match(line)
        if m_concat:
            indent, var_name, prefix, bound_var, suffix = m_concat.groups()
            patched.append(f'{indent}{var_name} = "{prefix}?{suffix}"')
            pending_sql_var = (var_name, [bound_var.strip()])
            notes.append(f"Converted '+' string-concatenated SQL in '{var_name}' to '?' parameter binding")
            continue

        # Direct inline cursor.execute(f"SELECT ...")
        m_inline_f = re.match(
            r'^(\s*)([\w\.]+)\.execute\(\s*f(["\'])(SELECT|INSERT|UPDATE|DELETE)(.+)\3\s*\)\s*$',
            line,
            re.IGNORECASE,
        )
        if m_inline_f:
            indent, cur_obj, quote, verb, rest = m_inline_f.groups()
            vars_found = [v.strip() for v in re.findall(r"\{([^}]+)\}", rest)]
            clean_rest = re.sub(r"'\{[^}]+\}'|\{[^}]+\}", "?", rest)
            tuple_str = "(" + ", ".join(vars_found) + ("," if len(vars_found) == 1 else "") + ")"
            patched.append(f'{indent}{cur_obj}.execute("{verb}{clean_rest}", {tuple_str})')
            notes.append(f"Parameterized inline f-string {cur_obj}.execute() call")
            continue

        # Attach bound tuple to cursor.execute(sql_var)
        if pending_sql_var is not None:
            sql_var, bound_vars = pending_sql_var
            exec_re = re.compile(rf"^(\s*)([\w\.]+)\.execute\(\s*{re.escape(sql_var)}\s*\)\s*$")
            m_exec = exec_re.match(line)
            if m_exec:
                indent, cur_obj = m_exec.groups()
                tuple_str = "(" + ", ".join(bound_vars) + ("," if len(bound_vars) == 1 else "") + ")"
                patched.append(f"{indent}{cur_obj}.execute({sql_var}, {tuple_str})")
                pending_sql_var = None
                continue

        patched.append(line)

    return patched, notes


def _patch_cmdi_in_function(fn_text: str) -> Tuple[str, List[str], bool]:
    """Rewrite subprocess.run(f'...', shell=True) into shell=False argv list with _validate_safe_cli_arg()."""
    notes: List[str] = []
    needs_cli_helper = False

    # Case A: python3 -c '...' {var} with shell=True
    py_inline_pat = re.compile(
        r'subprocess\.run\(\s*f"python3 -c \'([^\']+)\'\s+\{(\w+)\}"\s*,\s*shell=True\s*,',
        re.MULTILINE,
    )
    if py_inline_pat.search(fn_text):
        fn_text = py_inline_pat.sub(
            r'subprocess.run(["python3", "-c", "\1", _validate_safe_cli_arg(\2)], shell=False,',
            fn_text,
        )
        needs_cli_helper = True
        notes.append("Replaced shell=True command string with shell=False argv list and _validate_safe_cli_arg()")

    # Generic fallback for subprocess.run(f"cmd flag {var}", shell=True, ...)
    generic_fcmd = re.compile(
        r'subprocess\.run\(\s*f"([A-Za-z0-9_\-/\.]+)((?:\s+[A-Za-z0-9_\-\.]+)*)\s+\{(\w+)\}"\s*,\s*shell=True',
        re.MULTILINE,
    )
    m_gen = generic_fcmd.search(fn_text)
    if m_gen:
        binary, flags_raw, var_name = m_gen.groups()
        flags = [f'"{tok}"' for tok in flags_raw.strip().split() if tok]
        argv_items = ", ".join([f'"{binary}"'] + flags + [f"_validate_safe_cli_arg({var_name})"])
        fn_text = generic_fcmd.sub(f"subprocess.run([{argv_items}], shell=False", fn_text)
        needs_cli_helper = True
        notes.append(f"Converted generic subprocess.run(f'{binary} ...', shell=True) to shell=False argv list")

    return fn_text, notes, needs_cli_helper


def _patch_ssrf_in_function(fn_lines: List[str], has_allowed_const: bool) -> Tuple[List[str], List[str], bool]:
    """Insert _validate_https_allowlist() guard at the start of a reachable outbound HTTP helper."""
    if any("_validate_https_allowlist" in ln for ln in fn_lines):
        return fn_lines, [], False

    # Identify URL parameter from def header
    def_line = fn_lines[0]
    m_def = re.match(r"^(\s*)def\s+\w+\(\s*(\w+)", def_line)
    if not m_def:
        return fn_lines, [], False
    base_indent, first_param = m_def.groups()
    body_indent = base_indent + "    "
    hosts_arg = "ALLOWED_PARTNER_HOSTS" if has_allowed_const else "()"
    guard_line = f"{body_indent}{first_param} = _validate_https_allowlist({first_param}, {hosts_arg})"
    patched = [fn_lines[0], guard_line] + fn_lines[1:]
    return patched, [f"Inserted _validate_https_allowlist({first_param}, {hosts_arg}) before outbound HTTP call"], True


def _patch_deser_in_function(fn_text: str) -> Tuple[str, List[str], bool]:
    """Replace pickle.loads(x) with json.loads(x.decode('utf-8') if isinstance(x, (bytes, bytearray)) else x)."""
    pat = re.compile(r"pickle\.loads\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
    if not pat.search(fn_text):
        return fn_text, [], False
    patched = pat.sub(
        r'json.loads(\1.decode("utf-8") if isinstance(\1, (bytes, bytearray)) else \1)',
        fn_text,
    )
    return patched, ["Replaced unsafe pickle.loads() with UTF-8 json.loads()"], True


def synthesize_minimal_patch(source_code: str, filename: str = "service.py") -> Dict[str, Any]:
    """Generate a minimal AST-scoped security remediation touching ONLY reachable vulnerable paths."""
    initial_scan = scan_python_reachability(source_code, filename=filename)
    reachable = initial_scan["reachable_findings"]
    if not reachable:
        return {
            "patched_source": source_code,
            "unified_diff": "",
            "changed_lines_count": 0,
            "patch_actions": [],
            "initial_scan": initial_scan,
        }

    lines = source_code.splitlines()
    fn_ranges = _extract_function_ranges(source_code)
    has_allowed_const = "ALLOWED_PARTNER_HOSTS" in source_code

    rules_by_func: Dict[str, Set[str]] = {}
    secret_lines: Set[int] = set()
    for f in reachable:
        if f["rule_id"] == "SEC-AST-SECRET-05":
            secret_lines.add(int(f["lineno"]))
        else:
            rules_by_func.setdefault(f["function_name"], set()).add(f["rule_id"])

    patch_actions: List[str] = []
    need_ssrf_helper = False
    need_cli_helper = False
    need_json_import = False
    need_os_import = False

    # 1. Replace module-level hardcoded secrets referenced on reachable paths
    for lineno in sorted(secret_lines):
        idx = lineno - 1
        if 0 <= idx < len(lines):
            m_sec = re.match(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(["\']).+\3\s*$', lines[idx])
            if m_sec:
                indent, sym, _ = m_sec.groups()
                lines[idx] = f'{indent}{sym} = os.environ.get("{sym}", "")'
                need_os_import = True
                patch_actions.append(f"Replaced hardcoded secret '{sym}' at L{lineno} with os.environ.get('{sym}', '')")

    # 2. Patch reachable functions from bottom to top so line numbers stay exact
    sorted_funcs = sorted(
        ((fn, fn_ranges[fn]) for fn in rules_by_func if fn in fn_ranges),
        key=lambda item: item[1][0],
        reverse=True,
    )

    for fn_name, (start_ln, end_ln) in sorted_funcs:
        rset = rules_by_func[fn_name]
        fn_slice = lines[start_ln - 1 : end_ln]

        if "SEC-AST-SQLI-01" in rset:
            fn_slice, notes = _patch_sql_lines_in_function(fn_slice)
            patch_actions.extend(f"{fn_name}(): {n}" for n in notes)

        if "SEC-AST-SSRF-03" in rset:
            fn_slice, notes, used_ssrf = _patch_ssrf_in_function(fn_slice, has_allowed_const)
            need_ssrf_helper = need_ssrf_helper or used_ssrf
            patch_actions.extend(f"{fn_name}(): {n}" for n in notes)

        fn_text = "\n".join(fn_slice)
        if "SEC-AST-CMDI-02" in rset:
            fn_text, notes, used_cli = _patch_cmdi_in_function(fn_text)
            need_cli_helper = need_cli_helper or used_cli
            patch_actions.extend(f"{fn_name}(): {n}" for n in notes)

        if "SEC-AST-DESER-04" in rset:
            fn_text, notes, used_json = _patch_deser_in_function(fn_text)
            need_json_import = need_json_import or used_json
            patch_actions.extend(f"{fn_name}(): {n}" for n in notes)

        lines[start_ln - 1 : end_ln] = fn_text.splitlines()

    # 3. Ensure required stdlib imports & helper functions exist cleanly after imports
    joined_now = "\n".join(lines)
    insert_idx = 0
    for i, ln in enumerate(lines):
        if ln.startswith("import ") or ln.startswith("from "):
            insert_idx = i + 1

    extra_imports: List[str] = []
    if need_json_import and not re.search(r"^\s*import\s+json\b", joined_now, re.MULTILINE):
        extra_imports.append("import json")
    if need_os_import and not re.search(r"^\s*import\s+os\b", joined_now, re.MULTILINE):
        extra_imports.append("import os")

    helper_blocks: List[str] = []
    if need_ssrf_helper and "def _validate_https_allowlist" not in joined_now:
        helper_blocks.extend(SSRF_HELPER_BLOCK.strip().splitlines())
        helper_blocks.append("")
    if need_cli_helper and "def _validate_safe_cli_arg" not in joined_now:
        helper_blocks.extend(CLI_GUARD_HELPER_BLOCK.strip().splitlines())
        helper_blocks.append("")

    if extra_imports or helper_blocks:
        addition = extra_imports + ([""] if extra_imports else []) + helper_blocks
        lines = lines[:insert_idx] + addition + lines[insert_idx:]

    patched_source = "\n".join(lines) + "\n"
    diff_lines = list(
        difflib.unified_diff(
            source_code.splitlines(),
            patched_source.splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
    )
    changed_count = sum(
        1 for d in diff_lines if (d.startswith("+") or d.startswith("-")) and not d.startswith(("+++", "---"))
    )

    return {
        "patched_source": patched_source,
        "unified_diff": "\n".join(diff_lines),
        "changed_lines_count": changed_count,
        "patch_actions": patch_actions,
        "initial_scan": initial_scan,
    }


def run_closed_loop_autopatch(
    service_id: Optional[str] = None,
    source_code: Optional[str] = None,
    test_code: Optional[str] = None,
    filename: str = "custom_service.py",
    test_filename: str = "test_custom_service.py",
) -> Dict[str, Any]:
    """Execute full Closed-Loop Auto-Patch + AST Re-Scan + `/tmp` Unit-Test Suite Verification."""
    t0 = time.perf_counter()

    if service_id and service_id in SERVICE_REPOS:
        repo = SERVICE_REPOS[service_id]
        source_code = source_code or repo["source_code"]
        test_code = test_code if test_code is not None else repo["test_code"]
        filename = repo["filename"]
        test_filename = repo["test_filename"]
    elif not source_code:
        raise ValueError("Either a valid service_id or source_code must be provided")

    synth = synthesize_minimal_patch(source_code=source_code, filename=filename)
    patched_source = synth["patched_source"]
    before_scan = synth["initial_scan"]

    # Gate 1: Deterministic AST Syntax Parse Check
    syntax_valid = True
    syntax_error = ""
    try:
        ast.parse(patched_source, filename=filename)
    except SyntaxError as exc:
        syntax_valid = False
        syntax_error = str(exc)

    # Gate 2: Re-run AST Reachability Scanner on Patched Code
    after_scan = scan_python_reachability(patched_source, filename=filename) if syntax_valid else before_scan

    # Gate 3: Execute Behavioral `unittest` Suite in Isolated `/tmp` Sandbox
    sandbox_dir = Path(tempfile.mkdtemp(prefix="secposture-verify-", dir="/tmp"))
    unit_test_passed = False
    tests_run = 0
    unittest_ms = 0.0
    unittest_output = ""

    try:
        (sandbox_dir / filename).write_text(patched_source, encoding="utf-8")
        if test_code:
            (sandbox_dir / test_filename).write_text(test_code, encoding="utf-8")
        else:
            # Synthesize smoke import & AST sanity test when custom snippet has no accompanying test file
            mod_name = Path(filename).stem
            auto_smoke = (
                "import unittest\n"
                f"import {mod_name}\n\n"
                "class SmokePatchTest(unittest.TestCase):\n"
                "    def test_module_imports_cleanly(self):\n"
                f"        self.assertIsNotNone({mod_name})\n"
            )
            (sandbox_dir / test_filename).write_text(auto_smoke, encoding="utf-8")

        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
            "PYTHONPATH": str(sandbox_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "CHECKOUT_HMAC_SECRET": "verified-sandbox-hmac-key-2026",
            "SESSION_VERIFY_KEY": "verified-sandbox-session-key-2026",
        }
        ut_t0 = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(sandbox_dir), "-v"],
            cwd=str(sandbox_dir),
            env=clean_env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=8.0,
        )
        unittest_ms = round((time.perf_counter() - ut_t0) * 1000.0, 2)
        combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        unittest_output = combined
        m_ran = re.search(r"Ran\s+(\d+)\s+test", combined)
        tests_run = int(m_ran.group(1)) if m_ran else 0
        unit_test_passed = proc.returncode == 0 and tests_run > 0
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    verified = bool(syntax_valid and after_scan["reachable_count"] == 0 and unit_test_passed)
    total_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "service_id": service_id or "custom-snippet",
        "filename": filename,
        "test_filename": test_filename,
        "status": "VERIFIED_READY_FOR_CR" if verified else "VERIFICATION_FAILED",
        "verified": verified,
        "total_loop_ms": total_ms,
        "unittest_ms": unittest_ms,
        "gates": {
            "ast_syntax_valid": syntax_valid,
            "syntax_error": syntax_error,
            "reachable_vulns_before": before_scan["reachable_count"],
            "reachable_vulns_after": after_scan["reachable_count"],
            "dead_code_untouched": after_scan["unreachable_count"],
            "unit_tests_run": tests_run,
            "unit_tests_passed": tests_run if unit_test_passed else 0,
            "unit_test_suite_ok": unit_test_passed,
        },
        "posture_score_before": before_scan["posture_score"],
        "posture_score_after": after_scan["posture_score"],
        "changed_lines_count": synth["changed_lines_count"],
        "patch_actions": synth["patch_actions"],
        "unified_diff": synth["unified_diff"],
        "patched_source": patched_source,
        "unittest_output": unittest_output,
        "before_scan": before_scan,
        "after_scan": after_scan,
    }
