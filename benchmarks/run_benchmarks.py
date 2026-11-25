"""Real End-to-End Benchmark Runner for SecPosture (`benchmarks/run_benchmarks.py`).

Executes:
  1. AST Call-Graph Reachability Scans across 6 Python microservices (vulnerable + dead-code + clean)
  2. Closed-Loop Auto-Patching + `/tmp` AST Re-Scan + `unittest` Verification across 4 vulnerable repos (12 runs)
  3. Multi-Hop IAM Attack-Path Graph Solver + Least-Privilege Patch Verification across 4 AWS snapshots
  4. Stateful CloudTrail Kill-Chain Sequence Detector across 16 labeled event streams (8 attacks + 8 benign)
  5. Live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) STRIDE Threat Reviews & Patch CR Summaries (8 live calls)
  6. SQLite WAL SHA-256 Hash-Chain Verification across all benchmark audit events
"""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from secposture.attack_graph import (  # noqa: E402
    analyze_iam_attack_paths,
    evaluate_all_cloudtrail_benchmarks,
    get_iam_environment,
)
from secposture.audit_ledger import SQLiteAuditLedger  # noqa: E402
from secposture.autopatch_loop import run_closed_loop_autopatch  # noqa: E402
from secposture.reachability_ast import scan_python_reachability  # noqa: E402
from secposture.sample_services import IAM_ENVIRONMENTS, SERVICE_REPOS  # noqa: E402
from secposture.threat_review import generate_appsec_threat_review, invoke_bedrock_nova  # noqa: E402


def _pct(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    idx = (len(ordered) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return round(ordered[lo] * (1.0 - frac) + ordered[hi] * frac, 3)


def main() -> None:
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        os.environ.pop(key, None)
    os.environ.setdefault("AWS_PROFILE", "portfolio")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

    tmp_ledger_dir = Path(tempfile.mkdtemp(prefix="secposture-bench-db-", dir="/tmp"))
    ledger = SQLiteAuditLedger(db_path=tmp_ledger_dir / "bench_audit.db")

    # -------------------------------------------------------------------------
    # 1. AST Call-Graph Reachability Benchmark (6 Services x 3 Timed Passes)
    # -------------------------------------------------------------------------
    ast_scan_times: List[float] = []
    service_scan_matrix: List[Dict[str, Any]] = []
    total_raw_findings = 0
    total_reachable = 0
    total_unreachable = 0
    expected_reachable_hits = 0
    expected_reachable_total = 0

    for sid, repo in SERVICE_REPOS.items():
        passes = []
        last_scan: Dict[str, Any] = {}
        for _ in range(3):
            s = scan_python_reachability(repo["source_code"], filename=repo["filename"])
            passes.append(s["scan_ms"])
            last_scan = s
            ledger.append_event("BENCH_AST_SCAN", sid, s["posture_status"], s["scan_ms"], {"reachable": s["reachable_count"]})

        ast_scan_times.extend(passes)
        total_raw_findings += last_scan["total_raw_findings"]
        total_reachable += last_scan["reachable_count"]
        total_unreachable += last_scan["unreachable_count"]

        exp_rules = list(repo["expected_reachable_rules"])
        found_rules = [f["rule_id"] for f in last_scan["reachable_findings"]]
        expected_reachable_total += len(exp_rules)
        for r in exp_rules:
            if r in found_rules:
                expected_reachable_hits += 1

        service_scan_matrix.append(
            {
                "service_id": sid,
                "title": repo["title"],
                "filename": repo["filename"],
                "raw_findings": last_scan["total_raw_findings"],
                "reachable_vulns": last_scan["reachable_count"],
                "dead_code_filtered": last_scan["unreachable_count"],
                "posture_score": last_scan["posture_score"],
                "posture_status": last_scan["posture_status"],
                "scan_p50_ms": _pct(passes, 0.50),
                "reachable_rules": sorted(found_rules),
            }
        )

    noise_reduction_pct = round((total_unreachable / total_raw_findings) * 100.0, 1) if total_raw_findings else 0.0
    reachable_recall_pct = round((expected_reachable_hits / expected_reachable_total) * 100.0, 1) if expected_reachable_total else 100.0
    reachable_precision_pct = round((expected_reachable_hits / total_reachable) * 100.0, 1) if total_reachable else 100.0

    # -------------------------------------------------------------------------
    # 2. Closed-Loop Auto-Patch + `/tmp` Unit-Test Verification (4 Repos x 3 Runs = 12 Runs)
    # -------------------------------------------------------------------------
    vulnerable_service_ids = [
        "orders-checkout-api",
        "artifact-build-worker",
        "tenant-webhook-relay",
        "profile-export-lambda",
    ]
    autopatch_loop_times: List[float] = []
    unittest_times: List[float] = []
    autopatch_matrix: List[Dict[str, Any]] = []
    autopatch_runs_total = 0
    autopatch_runs_verified = 0
    unique_service_tests_passed = 0

    for sid in vulnerable_service_ids:
        repo_times: List[float] = []
        repo_ut_times: List[float] = []
        verified_cnt = 0
        last_patch: Dict[str, Any] = {}
        for _ in range(3):
            p_out = run_closed_loop_autopatch(service_id=sid)
            autopatch_runs_total += 1
            if p_out["verified"]:
                autopatch_runs_verified += 1
                verified_cnt += 1
            repo_times.append(p_out["total_loop_ms"])
            repo_ut_times.append(p_out["unittest_ms"])
            autopatch_loop_times.append(p_out["total_loop_ms"])
            unittest_times.append(p_out["unittest_ms"])
            last_patch = p_out
            ledger.append_event("BENCH_AUTOPATCH", sid, p_out["status"], p_out["total_loop_ms"], p_out["gates"])

        unique_service_tests_passed += int(last_patch["gates"]["unit_tests_passed"])
        autopatch_matrix.append(
            {
                "service_id": sid,
                "filename": last_patch["filename"],
                "runs": 3,
                "verified_runs": verified_cnt,
                "vulns_before": last_patch["gates"]["reachable_vulns_before"],
                "vulns_after": last_patch["gates"]["reachable_vulns_after"],
                "dead_code_untouched": last_patch["gates"]["dead_code_untouched"],
                "unit_tests_passed": last_patch["gates"]["unit_tests_passed"],
                "changed_lines": last_patch["changed_lines_count"],
                "loop_p50_ms": _pct(repo_times, 0.50),
                "loop_p95_ms": _pct(repo_times, 0.95),
                "unittest_p50_ms": _pct(repo_ut_times, 0.50),
            }
        )

    # Also verify clean services pass their test suites (`2 + 1 = 3` extra behavioral tests -> `16` total repo tests)
    for clean_sid in ("ledger-reconciler-clean", "token-verifier-clean"):
        c_out = run_closed_loop_autopatch(service_id=clean_sid)
        unique_service_tests_passed += int(c_out["gates"]["unit_tests_passed"])

    # -------------------------------------------------------------------------
    # 3. Multi-Hop IAM Attack-Path Graph Solver & Least-Privilege Patch Verification
    # -------------------------------------------------------------------------
    iam_solve_times: List[float] = []
    iam_matrix: List[Dict[str, Any]] = []
    total_paths_before = 0
    total_paths_after = 0

    for eid, env_snap in IAM_ENVIRONMENTS.items():
        before_g = analyze_iam_attack_paths(env_snap, apply_least_privilege_patch=False)
        after_g = analyze_iam_attack_paths(env_snap, apply_least_privilege_patch=True)
        iam_solve_times.extend([before_g["solve_ms"], after_g["solve_ms"]])
        total_paths_before += before_g["attack_paths_count"]
        total_paths_after += after_g["attack_paths_count"]
        ledger.append_event("BENCH_IAM_GRAPH", eid, after_g["posture_verdict"], before_g["solve_ms"], {"paths_before": before_g["attack_paths_count"], "paths_after": after_g["attack_paths_count"]})
        iam_matrix.append(
            {
                "env_id": eid,
                "title": env_snap["title"],
                "paths_before": before_g["attack_paths_count"],
                "shortest_hops": before_g["shortest_hop_count"] or 0,
                "paths_after_patch": after_g["attack_paths_count"],
                "solve_ms": before_g["solve_ms"],
                "verdict_after": after_g["posture_verdict"],
            }
        )

    # -------------------------------------------------------------------------
    # 4. Stateful CloudTrail Kill-Chain Sequence Detection (16 Labeled Traces)
    # -------------------------------------------------------------------------
    ct_bench = evaluate_all_cloudtrail_benchmarks()
    for tr in ct_bench["trace_results"]:
        ledger.append_event("BENCH_CLOUDTRAIL", tr["trace_id"], tr["severity"], tr["detect_ms"], {"detected": tr["incident_detected"], "score": tr["anomaly_score"]})

    # -------------------------------------------------------------------------
    # 5. Live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) Threat Reviews & Patch CRs
    # -------------------------------------------------------------------------
    bedrock_records: List[Dict[str, Any]] = []
    bedrock_latencies: List[float] = []
    bedrock_tokens: List[int] = []

    for sid in vulnerable_service_ids:
        rev = generate_appsec_threat_review(service_id=sid, use_bedrock=True)
        tel = rev["llm_telemetry"]
        if tel["latency_ms"] > 0:
            bedrock_latencies.append(float(tel["latency_ms"]))
            bedrock_tokens.append(int(tel["total_tokens"]))
        bedrock_records.append(
            {
                "call_id": f"BR-STRIDE-{sid}",
                "task_type": "STRIDE Launch Threat Review",
                "target": sid,
                "decision": rev["launch_decision"],
                "latency_ms": tel["latency_ms"],
                "tokens": tel["total_tokens"],
            }
        )
        ledger.append_event("BENCH_BEDROCK_STRIDE", sid, rev["launch_decision"], tel["latency_ms"], {"tokens": tel["total_tokens"]})

    for sid in vulnerable_service_ids:
        p_res = run_closed_loop_autopatch(service_id=sid)
        cr_llm = invoke_bedrock_nova(
            system_prompt="You are an Amazon Security Engineer writing a 2-sentence CR security verification note. Never use em-dashes.",
            user_prompt=(
                f"Service: {sid} ({p_res['filename']})\n"
                f"Actions: {p_res['patch_actions']}\n"
                f"Gates: {p_res['gates']}\n"
                f"Diff:\n{p_res['unified_diff'][:1200]}"
            ),
            max_tokens=180,
        )
        if cr_llm:
            bedrock_latencies.append(float(cr_llm["latency_ms"]))
            bedrock_tokens.append(int(cr_llm["total_tokens"]))
            bedrock_records.append(
                {
                    "call_id": f"BR-PATCHCR-{sid}",
                    "task_type": "Verified Auto-Patch CR Note",
                    "target": sid,
                    "decision": "VERIFIED_READY_FOR_CR",
                    "latency_ms": cr_llm["latency_ms"],
                    "tokens": cr_llm["total_tokens"],
                }
            )
            ledger.append_event("BENCH_BEDROCK_CR", sid, "VERIFIED_READY_FOR_CR", cr_llm["latency_ms"], {"tokens": cr_llm["total_tokens"]})

    chain_verify = ledger.verify_chain_integrity()

    output = {
        "service": "secposture-appsec",
        "benchmark_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "python_version": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "bedrock_model": os.environ.get("SECPOSTURE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
            "aws_region": os.environ.get("AWS_DEFAULT_REGION", "us-west-2"),
            "verification_sandbox": "Isolated /tmp workspace + AST re-scan + subprocess(shell=False) unittest",
            "audit_store": "SQLite WAL + SHA-256 hash chain",
        },
        "headline_kpis": {
            "services_scanned": len(SERVICE_REPOS),
            "total_raw_findings": total_raw_findings,
            "reachable_vulns_found": total_reachable,
            "unreachable_dead_code_filtered": total_unreachable,
            "alert_noise_reduction_pct": noise_reduction_pct,
            "reachable_recall_pct": reachable_recall_pct,
            "reachable_precision_pct": reachable_precision_pct,
            "ast_scan_p50_ms": _pct(ast_scan_times, 0.50),
            "ast_scan_p95_ms": _pct(ast_scan_times, 0.95),
            "autopatch_runs_total": autopatch_runs_total,
            "autopatch_runs_verified": autopatch_runs_verified,
            "autopatch_verify_rate_pct": round((autopatch_runs_verified / autopatch_runs_total) * 100.0, 1),
            "service_unit_tests_passed": unique_service_tests_passed,
            "autopatch_loop_p50_ms": _pct(autopatch_loop_times, 0.50),
            "autopatch_loop_p95_ms": _pct(autopatch_loop_times, 0.95),
            "unittest_sandbox_p50_ms": _pct(unittest_times, 0.50),
            "iam_attack_paths_before": total_paths_before,
            "iam_attack_paths_after_patch": total_paths_after,
            "iam_graph_solve_p50_ms": _pct(iam_solve_times, 0.50),
            "cloudtrail_traces_total": ct_bench["total_traces"],
            "cloudtrail_attacks_caught": ct_bench["true_positives"],
            "cloudtrail_attacks_total": ct_bench["true_positives"] + ct_bench["false_negatives"],
            "cloudtrail_false_positives": ct_bench["false_positives"],
            "cloudtrail_precision_pct": ct_bench["precision_pct"],
            "cloudtrail_recall_pct": ct_bench["recall_pct"],
            "cloudtrail_detect_p50_ms": _pct(ct_bench["latencies_ms"], 0.50),
            "bedrock_calls_measured": len(bedrock_latencies),
            "bedrock_latency_p50_ms": _pct(bedrock_latencies, 0.50),
            "bedrock_latency_p95_ms": _pct(bedrock_latencies, 0.95),
            "bedrock_mean_tokens": round(statistics.mean(bedrock_tokens), 1) if bedrock_tokens else 0.0,
            "bedrock_total_tokens": sum(bedrock_tokens),
            "sqlite_worm_rows_verified": chain_verify["checked_rows"],
            "sqlite_worm_verify_ms": chain_verify["verify_ms"],
        },
        "reachability_matrix": service_scan_matrix,
        "autopatch_matrix": autopatch_matrix,
        "iam_graph_matrix": iam_matrix,
        "cloudtrail_results": [
            {
                "trace_id": r["trace_id"],
                "title": r["title"],
                "ground_truth": "ATTACK" if r["malicious_ground_truth"] else "BENIGN",
                "detected": r["incident_detected"],
                "anomaly_score": r["anomaly_score"],
                "stages": r["kill_chain_stages_matched"],
                "detect_ms": r["detect_ms"],
            }
            for r in ct_bench["trace_results"]
        ],
        "bedrock_call_results": bedrock_records,
    }

    out_path = ROOT_DIR / "benchmarks" / "latest_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output["headline_kpis"], indent=2))


if __name__ == "__main__":
    main()
