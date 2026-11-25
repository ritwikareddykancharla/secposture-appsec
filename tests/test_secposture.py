"""Comprehensive Unit Test Suite for SecPosture (`tests/test_secposture.py`)."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secposture.attack_graph import (
    analyze_iam_attack_paths,
    detect_cloudtrail_kill_chain,
    evaluate_all_cloudtrail_benchmarks,
    get_iam_environment,
)
from secposture.audit_ledger import SQLiteAuditLedger
from secposture.autopatch_loop import run_closed_loop_autopatch
from secposture.reachability_ast import scan_python_reachability
from secposture.sample_services import SERVICE_REPOS
from secposture.server import lambda_handler, route_api_request
from secposture.threat_review import generate_appsec_threat_review


class TestSecPostureSuite(unittest.TestCase):
    def test_01_ast_reachability_separates_reachable_from_dead_code(self) -> None:
        repo = SERVICE_REPOS["orders-checkout-api"]
        scan = scan_python_reachability(repo["source_code"], filename=repo["filename"])
        self.assertEqual(scan["reachable_count"], 3)
        self.assertEqual(scan["unreachable_count"], 2)
        self.assertEqual(scan["posture_status"], "BLOCK_LAUNCH")
        found_rules = {f["rule_id"] for f in scan["reachable_findings"]}
        self.assertEqual(found_rules, {"SEC-AST-SQLI-01", "SEC-AST-SSRF-03", "SEC-AST-SECRET-05"})
        for dead in scan["unreachable_findings"]:
            self.assertEqual(dead["reachability"], "UNREACHABLE_DEAD_CODE")

    def test_02_clean_service_with_dead_code_scores_launch_ready(self) -> None:
        repo = SERVICE_REPOS["ledger-reconciler-clean"]
        scan = scan_python_reachability(repo["source_code"], filename=repo["filename"])
        self.assertEqual(scan["reachable_count"], 0)
        self.assertEqual(scan["unreachable_count"], 1)
        self.assertEqual(scan["posture_status"], "LAUNCH_READY")
        self.assertGreaterEqual(scan["posture_score"], 95)

    def test_03_closed_loop_autopatch_orders_service_passes_all_gates(self) -> None:
        res = run_closed_loop_autopatch(service_id="orders-checkout-api")
        self.assertTrue(res["verified"], msg=res["unittest_output"])
        self.assertEqual(res["status"], "VERIFIED_READY_FOR_CR")
        self.assertEqual(res["gates"]["reachable_vulns_before"], 3)
        self.assertEqual(res["gates"]["reachable_vulns_after"], 0)
        self.assertEqual(res["gates"]["dead_code_untouched"], 2)
        self.assertEqual(res["gates"]["unit_tests_run"], 4)
        self.assertTrue(res["gates"]["unit_test_suite_ok"])

    def test_04_closed_loop_autopatch_build_worker_cmdi_and_pickle(self) -> None:
        res = run_closed_loop_autopatch(service_id="artifact-build-worker")
        self.assertTrue(res["verified"], msg=res["unittest_output"])
        self.assertEqual(res["gates"]["reachable_vulns_before"], 2)
        self.assertEqual(res["gates"]["reachable_vulns_after"], 0)
        self.assertEqual(res["gates"]["unit_tests_run"], 3)

    def test_05_closed_loop_autopatch_webhook_relay_and_profile_export(self) -> None:
        relay = run_closed_loop_autopatch(service_id="tenant-webhook-relay")
        self.assertTrue(relay["verified"], msg=relay["unittest_output"])
        self.assertEqual(relay["gates"]["reachable_vulns_after"], 0)

        prof = run_closed_loop_autopatch(service_id="profile-export-lambda")
        self.assertTrue(prof["verified"], msg=prof["unittest_output"])
        self.assertEqual(prof["gates"]["reachable_vulns_before"], 3)
        self.assertEqual(prof["gates"]["reachable_vulns_after"], 0)

    def test_06_iam_attack_graph_finds_shortest_multihop_escalation(self) -> None:
        env = get_iam_environment("env-checkout-prod")
        graph = analyze_iam_attack_paths(env, apply_least_privilege_patch=False)
        self.assertGreaterEqual(graph["attack_paths_count"], 2)
        self.assertEqual(graph["shortest_hop_count"], 3)
        self.assertEqual(graph["posture_verdict"], "CROWN_JEWEL_EXPOSED")
        top = graph["attack_paths"][0]
        self.assertIn("SEC-IAM-PASSROLE-01", top["toxic_rules"])

    def test_07_iam_least_privilege_patch_eliminates_all_crown_jewel_paths(self) -> None:
        for env_id in ("env-checkout-prod", "env-ci-pipeline", "env-analytics-lake", "env-hardened-zero-trust"):
            patched = analyze_iam_attack_paths(get_iam_environment(env_id), apply_least_privilege_patch=True)
            self.assertEqual(patched["attack_paths_count"], 0, msg=f"Remaining path in {env_id}")
            self.assertEqual(patched["posture_verdict"], "LEAST_PRIVILEGE_VERIFIED")

    def test_08_cloudtrail_kill_chain_detector_precision_and_recall(self) -> None:
        bench = evaluate_all_cloudtrail_benchmarks()
        self.assertEqual(bench["total_traces"], 16)
        self.assertEqual(bench["true_positives"], 8)
        self.assertEqual(bench["false_positives"], 0)
        self.assertEqual(bench["precision_pct"], 100.0)
        self.assertEqual(bench["recall_pct"], 100.0)

    def test_09_stride_threat_review_anchors_file_lines_and_arns(self) -> None:
        rev = generate_appsec_threat_review(
            service_id="orders-checkout-api",
            env_id="env-checkout-prod",
            use_bedrock=False,
        )
        self.assertEqual(rev["launch_decision"], "BLOCK_LAUNCH_UNTIL_PATCHED")
        self.assertEqual(len(rev["stride_matrix"]), 6)
        self.assertGreaterEqual(rev["open_stride_categories"], 4)

    def test_10_sqlite_worm_audit_ledger_detects_single_row_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / "test_audit.db"
            ledger = SQLiteAuditLedger(db_path=db_file)
            ledger.append_event("AST_SCAN", "svc-a", "BLOCK_LAUNCH", 1.2, {"reachable": 2})
            ledger.append_event("AUTOPATCH", "svc-a", "VERIFIED_READY_FOR_CR", 14.8, {"tests": 4})
            ok = ledger.verify_chain_integrity()
            self.assertTrue(ok["valid"])
            self.assertEqual(ok["checked_rows"], 2)

            # Tamper with row 1 directly in SQLite
            conn = sqlite3.connect(str(db_file))
            conn.execute("UPDATE audit_events SET verdict = 'LAUNCH_READY' WHERE seq = 1")
            conn.commit()
            conn.close()

            broken = ledger.verify_chain_integrity()
            self.assertFalse(broken["valid"])
            self.assertEqual(broken["broken_at_event_id"], "SP-AUD-00001")

    def test_11_api_router_and_lambda_handler_endpoints(self) -> None:
        st, health = route_api_request("GET", "/api/health", {}, {})
        self.assertEqual(st, 200)
        self.assertEqual(health["status"], "ok")

        event = {
            "rawPath": "/api/patch/verify",
            "requestContext": {"http": {"method": "POST"}},
            "body": json.dumps({"service_id": "tenant-webhook-relay", "include_bedrock_cr": False}),
        }
        resp = lambda_handler(event)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["gates"]["reachable_vulns_after"], 0)

    def test_12_custom_snippet_scan_and_autopatch_via_api(self) -> None:
        custom_py = (
            "import sqlite3\n"
            "def lambda_handler(event, conn):\n"
            "    uid = event.get('uid', '')\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(f\"SELECT email FROM users WHERE uid = '{uid}'\")\n"
            "    return cur.fetchall()\n"
        )
        st, patched = route_api_request("POST", "/api/patch/verify", {}, {"source_code": custom_py, "filename": "custom_api.py"})
        self.assertEqual(st, 200)
        self.assertTrue(patched["verified"])
        self.assertEqual(patched["gates"]["reachable_vulns_before"], 1)
        self.assertEqual(patched["gates"]["reachable_vulns_after"], 0)


if __name__ == "__main__":
    unittest.main()
