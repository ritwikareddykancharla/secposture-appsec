"""Realistic Python Microservice Fixtures, Unit Test Suites, IAM Snapshots & CloudTrail Streams.

All code samples and IAM/CloudTrail fixtures are synthetic defensive benchmarks designed for
testing static AST reachability analysis, least-privilege IAM graph pathfinding, and closed-loop
unit-test-verified code patching.
"""
from __future__ import annotations

from typing import Any, Dict, List

SERVICE_REPOS: Dict[str, Dict[str, Any]] = {
    "orders-checkout-api": {
        "service_id": "orders-checkout-api",
        "title": "Orders & Checkout Ledger Service",
        "owner_team": "Commerce Payments Platform",
        "tier": "Tier-1 Production",
        "filename": "orders_service.py",
        "test_filename": "test_orders_service.py",
        "env_id": "env-checkout-prod",
        "description": "Handles order search, receipt signing, and partner webhook notifications.",
        "expected_reachable_rules": ["SEC-AST-SQLI-01", "SEC-AST-SSRF-03", "SEC-AST-SECRET-05"],
        "expected_unreachable_count": 2,
        "source_code": '''"""Orders & Checkout Ledger Microservice."""
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import urllib.request

ALLOWED_PARTNER_HOSTS = ("hooks.stripe-partner.example", "events.shipping-partner.example")
CHECKOUT_HMAC_SECRET = "secp_live_hmac_9f82c104a7b3e6d19021ab"


def route(path: str, methods=("GET",)):
    def decorator(fn):
        fn._http_route = path
        fn._http_methods = methods
        return fn
    return decorator


def fetch_tenant_orders(conn: sqlite3.Connection, tenant_id: str, status_filter: str):
    cursor = conn.cursor()
    query = f"SELECT order_id, total_cents, status FROM orders WHERE tenant_id = '{tenant_id}' AND status = '{status_filter}'"
    cursor.execute(query)
    return [
        {"order_id": row[0], "total_cents": row[1], "status": row[2]}
        for row in cursor.fetchall()
    ]


def sign_checkout_receipt(order_id: str, total_cents: int) -> str:
    signing_key = CHECKOUT_HMAC_SECRET or os.environ.get("CHECKOUT_HMAC_SECRET", "dev-test-hmac-key")
    msg = f"{order_id}:{total_cents}".encode("utf-8")
    return hmac.new(signing_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def notify_partner_webhook(webhook_url: str, payload: dict, opener=None) -> int:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook_url, data=body, headers={"Content-Type": "application/json"})
    if opener is not None:
        return opener(req)
    with urllib.request.urlopen(webhook_url, data=body, timeout=3.0) as resp:
        return int(resp.status)


@route("/orders/search", methods=("POST",))
def search_orders_endpoint(conn: sqlite3.Connection, request_body: dict):
    tenant_id = str(request_body.get("tenant_id", ""))
    status_filter = str(request_body.get("status", "PAID"))
    rows = fetch_tenant_orders(conn, tenant_id, status_filter)
    return {"count": len(rows), "orders": rows}


def lambda_handler(event: dict, context=None, opener=None):
    order_id = str(event.get("order_id", "ord-100"))
    total_cents = int(event.get("total_cents", 2500))
    webhook_url = str(event.get("partner_webhook_url", "https://hooks.stripe-partner.example/v1/paid"))
    sig = sign_checkout_receipt(order_id, total_cents)
    status_code = notify_partner_webhook(
        webhook_url,
        {"order_id": order_id, "total_cents": total_cents, "signature": sig},
        opener=opener,
    )
    return {"order_id": order_id, "signature": sig, "webhook_status": status_code}


# --- Deprecated V1 helpers retained in module but unreachable from any entrypoint ---
def _legacy_v1_archive_lookup(conn: sqlite3.Connection, account_code: str):
    cur = conn.cursor()
    cur.execute("SELECT order_id FROM orders WHERE tenant_id = '%s'" % account_code)
    return cur.fetchall()


def _deprecated_local_tar_backup(archive_name: str):
    return subprocess.run(f"tar -czf /tmp/{archive_name}.tgz /tmp", shell=True, capture_output=True, text=True)
''',
        "test_code": '''"""Behavioral unit tests for orders_service."""
import os
import sqlite3
import unittest
import orders_service


class TestOrdersService(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("CHECKOUT_HMAC_SECRET", "unit-test-hmac-secret-key-01")
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE orders (order_id TEXT, tenant_id TEXT, total_cents INTEGER, status TEXT)"
        )
        self.conn.executemany(
            "INSERT INTO orders VALUES (?, ?, ?, ?)",
            [
                ("ord-01", "t-acme", 4200, "PAID"),
                ("ord-02", "t-acme", 1900, "REFUNDED"),
                ("ord-03", "t-other", 9900, "PAID"),
            ],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_search_orders_returns_matching_tenant_rows(self):
        res = orders_service.search_orders_endpoint(
            self.conn, {"tenant_id": "t-acme", "status": "PAID"}
        )
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["orders"][0]["order_id"], "ord-01")

    def test_search_orders_treats_quotes_as_literal_filter(self):
        res = orders_service.search_orders_endpoint(
            self.conn, {"tenant_id": "t-acme", "status": "PAID' OR '1'='1"}
        )
        self.assertEqual(res["count"], 0)

    def test_lambda_handler_allows_trusted_https_partner(self):
        out = orders_service.lambda_handler(
            {
                "order_id": "ord-01",
                "total_cents": 4200,
                "partner_webhook_url": "https://hooks.stripe-partner.example/v1/notify",
            },
            opener=lambda req: 202,
        )
        self.assertEqual(out["webhook_status"], 202)
        self.assertEqual(len(out["signature"]), 64)

    def test_webhook_rejects_untrusted_internal_metadata_url(self):
        with self.assertRaises(ValueError):
            orders_service.notify_partner_webhook(
                "http://169.254.169.254/latest/meta-data/iam/",
                {"order_id": "ord-01"},
                opener=lambda req: 200,
            )


if __name__ == "__main__":
    unittest.main()
''',
    },
    "artifact-build-worker": {
        "service_id": "artifact-build-worker",
        "title": "Artifact Checksum & Manifest Worker",
        "owner_team": "Developer Build Systems",
        "tier": "Tier-1 Build Pipeline",
        "filename": "build_worker.py",
        "test_filename": "test_build_worker.py",
        "env_id": "env-ci-pipeline",
        "description": "Verifies SHA-256 digests of uploaded build artifacts and parses cached build manifests.",
        "expected_reachable_rules": ["SEC-AST-CMDI-02", "SEC-AST-DESER-04"],
        "expected_unreachable_count": 2,
        "source_code": '''"""Artifact Checksum & Manifest Worker."""
import json
import os
import pickle
import subprocess


def route(path: str, methods=("POST",)):
    def decorator(fn):
        fn._http_route = path
        fn._http_methods = methods
        return fn
    return decorator


def compute_file_sha256(file_path: str) -> str:
    proc = subprocess.run(
        f"python3 -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' {file_path}",
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip().split()[0]


def parse_cached_manifest(raw_manifest: bytes) -> dict:
    data = pickle.loads(raw_manifest)
    if not isinstance(data, dict):
        raise ValueError("Manifest payload must decode to a JSON object")
    return data


@route("/artifacts/inspect", methods=("POST",))
def inspect_artifact_endpoint(request_body: dict) -> dict:
    artifact_path = str(request_body.get("artifact_path", ""))
    digest = compute_file_sha256(artifact_path)
    return {"artifact_path": artifact_path, "sha256": digest}


def lambda_handler(event: dict, context=None) -> dict:
    raw_blob = event.get("manifest_bytes", b'{"package":"core","version":"1.2.0"}')
    if isinstance(raw_blob, str):
        raw_blob = raw_blob.encode("utf-8")
    manifest = parse_cached_manifest(raw_blob)
    return {"package": manifest.get("package", "unknown"), "version": manifest.get("version", "0.0.0")}


# --- Unreachable legacy helpers ---
def _unused_legacy_pickle_restore(blob: bytes):
    return pickle.loads(blob)


def _unused_debug_uname(extra_flag: str):
    return os.system("uname " + extra_flag)
''',
        "test_code": '''"""Behavioral unit tests for build_worker."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import build_worker


class TestBuildWorker(unittest.TestCase):
    def test_compute_file_sha256_matches_expected_digest(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as fp:
            fp.write(b"secposture-deterministic-artifact-bytes")
            tmp_path = fp.name
        try:
            expected = hashlib.sha256(b"secposture-deterministic-artifact-bytes").hexdigest()
            actual = build_worker.inspect_artifact_endpoint({"artifact_path": tmp_path})["sha256"]
            self.assertEqual(actual, expected)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_compute_file_sha256_blocks_shell_chaining_filename(self):
        with self.assertRaises(ValueError):
            build_worker.compute_file_sha256("/tmp/nonexistent_file.bin; echo injected")

    def test_lambda_handler_parses_json_manifest_safely(self):
        payload = json.dumps({"package": "auth-sdk", "version": "2.4.1"}).encode("utf-8")
        out = build_worker.lambda_handler({"manifest_bytes": payload})
        self.assertEqual(out["package"], "auth-sdk")
        self.assertEqual(out["version"], "2.4.1")


if __name__ == "__main__":
    unittest.main()
''',
    },
    "tenant-webhook-relay": {
        "service_id": "tenant-webhook-relay",
        "title": "Multi-Tenant Webhook Relay Service",
        "owner_team": "Event Mesh Infrastructure",
        "tier": "Tier-1 Edge Service",
        "filename": "webhook_relay.py",
        "test_filename": "test_webhook_relay.py",
        "env_id": "env-analytics-lake",
        "description": "Dispatches outbound customer webhooks and queries per-webhook delivery logs.",
        "expected_reachable_rules": ["SEC-AST-SSRF-03", "SEC-AST-SQLI-01"],
        "expected_unreachable_count": 2,
        "source_code": '''"""Multi-Tenant Webhook Relay Service."""
import sqlite3
import urllib.request

ALLOWED_PARTNER_HOSTS = ("events.customer-gateway.example", "webhook.enterprise-partner.example")


def route(path: str, methods=("GET",)):
    def decorator(fn):
        fn._http_route = path
        fn._http_methods = methods
        return fn
    return decorator


def dispatch_outbound_http(target_url: str, body_bytes: bytes, opener=None) -> int:
    req = urllib.request.Request(target_url, data=body_bytes, headers={"Content-Type": "application/json"})
    if opener is not None:
        return opener(req)
    with urllib.request.urlopen(target_url, data=body_bytes, timeout=3.0) as resp:
        return int(resp.status)


def query_delivery_history(conn: sqlite3.Connection, webhook_id: str):
    cursor = conn.cursor()
    sql = "SELECT delivery_id, status_code FROM deliveries WHERE webhook_id = '" + webhook_id + "'"
    cursor.execute(sql)
    return [{"delivery_id": r[0], "status_code": r[1]} for r in cursor.fetchall()]


@route("/webhooks/deliver", methods=("POST",))
def deliver_webhook_endpoint(request_body: dict, opener=None) -> dict:
    target_url = str(request_body.get("target_url", ""))
    raw = str(request_body.get("payload", "{}")).encode("utf-8")
    code = dispatch_outbound_http(target_url, raw, opener=opener)
    return {"delivered": code < 400, "status_code": code}


@route("/webhooks/history", methods=("GET",))
def delivery_history_endpoint(conn: sqlite3.Connection, webhook_id: str) -> dict:
    items = query_delivery_history(conn, webhook_id)
    return {"webhook_id": webhook_id, "deliveries": items}


# --- Unreachable dead-code helpers ---
def _old_cleanup_deliveries(conn: sqlite3.Connection, cutoff_day: str):
    cur = conn.cursor()
    cur.execute(f"DELETE FROM deliveries WHERE created_day = '{cutoff_day}'")


def _unused_internal_ping(ping_url: str):
    return urllib.request.urlopen(ping_url, timeout=1.0)
''',
        "test_code": '''"""Behavioral unit tests for webhook_relay."""
import sqlite3
import unittest
import webhook_relay


class TestWebhookRelay(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE deliveries (delivery_id TEXT, webhook_id TEXT, status_code INTEGER)")
        self.conn.executemany(
            "INSERT INTO deliveries VALUES (?, ?, ?)",
            [("del-1", "wh-alpha", 200), ("del-2", "wh-beta", 503)],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_delivery_history_filters_exact_webhook(self):
        out = webhook_relay.delivery_history_endpoint(self.conn, "wh-alpha")
        self.assertEqual(len(out["deliveries"]), 1)
        self.assertEqual(out["deliveries"][0]["delivery_id"], "del-1")

    def test_delivery_history_blocks_sql_tautology_input(self):
        out = webhook_relay.delivery_history_endpoint(self.conn, "wh-alpha' OR '1'='1")
        self.assertEqual(len(out["deliveries"]), 0)

    def test_deliver_webhook_enforces_https_allowlist(self):
        ok = webhook_relay.deliver_webhook_endpoint(
            {"target_url": "https://events.customer-gateway.example/ingest", "payload": '{"ok":true}'},
            opener=lambda req: 200,
        )
        self.assertTrue(ok["delivered"])
        with self.assertRaises(ValueError):
            webhook_relay.deliver_webhook_endpoint(
                {"target_url": "http://127.0.0.1:8080/internal-admin", "payload": "{}"},
                opener=lambda req: 200,
            )


if __name__ == "__main__":
    unittest.main()
''',
    },
    "profile-export-lambda": {
        "service_id": "profile-export-lambda",
        "title": "Customer Profile Export Lambda",
        "owner_team": "Identity & Compliance Tools",
        "tier": "Tier-2 Internal Tooling",
        "filename": "profile_export.py",
        "test_filename": "test_profile_export.py",
        "env_id": "env-checkout-prod",
        "description": "Exports GDPR profile snapshots, compresses export files, and decodes export job state.",
        "expected_reachable_rules": ["SEC-AST-SQLI-01", "SEC-AST-CMDI-02", "SEC-AST-DESER-04"],
        "expected_unreachable_count": 1,
        "source_code": '''"""Customer Profile Export Lambda."""
import json
import pickle
import sqlite3
import subprocess


def load_profile_record(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    stmt = "SELECT user_id, email, region FROM profiles WHERE user_id = '{}'".format(user_id)
    cur.execute(stmt)
    row = cur.fetchone()
    return {"user_id": row[0], "email": row[1], "region": row[2]} if row else None


def count_lines_in_export(export_file: str) -> int:
    proc = subprocess.run(
        f"python3 -c 'import pathlib,sys; print(len(pathlib.Path(sys.argv[1]).read_text().splitlines()))' {export_file}",
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(proc.stdout.strip().split()[0])


def decode_job_preferences(raw_prefs: bytes) -> dict:
    prefs = pickle.loads(raw_prefs)
    return prefs if isinstance(prefs, dict) else {}


def lambda_handler(event: dict, conn: sqlite3.Connection = None) -> dict:
    user_id = str(event.get("user_id", ""))
    raw_prefs = event.get("prefs_bytes", b'{"format":"json"}')
    if isinstance(raw_prefs, str):
        raw_prefs = raw_prefs.encode("utf-8")
    prefs = decode_job_preferences(raw_prefs)
    profile = load_profile_record(conn, user_id) if conn is not None else None
    line_count = count_lines_in_export(event["export_file"]) if "export_file" in event else 0
    return {"profile": profile, "prefs": prefs, "line_count": line_count}


def _unused_legacy_sql(conn: sqlite3.Connection, email: str):
    cur = conn.cursor()
    cur.execute(f"SELECT user_id FROM profiles WHERE email = '{email}'")
    return cur.fetchall()
''',
        "test_code": '''"""Behavioral unit tests for profile_export."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
import profile_export


class TestProfileExport(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE profiles (user_id TEXT, email TEXT, region TEXT)")
        self.conn.executemany(
            "INSERT INTO profiles VALUES (?, ?, ?)",
            [("usr-10", "maya@example.org", "us-west-2"), ("usr-20", "liam@example.org", "eu-west-1")],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_profile_lookup_handles_quotes_safely(self):
        ok = profile_export.load_profile_record(self.conn, "usr-10")
        self.assertEqual(ok["email"], "maya@example.org")
        none_row = profile_export.load_profile_record(self.conn, "usr-10' OR '1'='1")
        self.assertIsNone(none_row)

    def test_line_count_and_json_preferences(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as fp:
            fp.write("line1\\nline2\\nline3\\n")
            tmp_name = fp.name
        try:
            out = profile_export.lambda_handler(
                {
                    "user_id": "usr-10",
                    "prefs_bytes": json.dumps({"format": "parquet"}).encode("utf-8"),
                    "export_file": tmp_name,
                },
                conn=self.conn,
            )
            self.assertEqual(out["line_count"], 3)
            self.assertEqual(out["prefs"]["format"], "parquet")
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def test_line_count_rejects_shell_metacharacters(self):
        with self.assertRaises(Exception):
            profile_export.count_lines_in_export("/tmp/missing.csv; id")


if __name__ == "__main__":
    unittest.main()
''',
    },
    "ledger-reconciler-clean": {
        "service_id": "ledger-reconciler-clean",
        "title": "Hardened Ledger Reconciler (Clean Live Path)",
        "owner_team": "Core Accounting Engineering",
        "tier": "Tier-1 Financial Controls",
        "filename": "reconciler_clean.py",
        "test_filename": "test_reconciler_clean.py",
        "env_id": "env-hardened-zero-trust",
        "description": "Parameterized SQL and JSON-only reconciler containing 1 uncalled legacy helper to test false-positive filtering.",
        "expected_reachable_rules": [],
        "expected_unreachable_count": 1,
        "source_code": '''"""Hardened Ledger Reconciler Service."""
import json
import os
import sqlite3
import subprocess


def route(path: str, methods=("GET",)):
    def decorator(fn):
        fn._http_route = path
        fn._http_methods = methods
        return fn
    return decorator


def query_batch_totals(conn: sqlite3.Connection, batch_id: str) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM ledger_entries WHERE batch_id = ?", (batch_id,))
    row = cur.fetchone()
    return int(row[0]) if row else 0


@route("/reconcile/summary", methods=("POST",))
def reconcile_summary_endpoint(conn: sqlite3.Connection, payload_json: str) -> dict:
    parsed = json.loads(payload_json)
    batch_id = str(parsed.get("batch_id", ""))
    total = query_batch_totals(conn, batch_id)
    return {"batch_id": batch_id, "total_cents": total, "env_key_set": bool(os.environ.get("RECON_SIGN_KEY", ""))}


def lambda_handler(event: dict, context=None) -> dict:
    proc = subprocess.run(["python3", "--version"], shell=False, capture_output=True, text=True, check=True)
    return {"runtime": proc.stdout.strip(), "status": "ok"}


# Uncalled legacy v0 helper retained during deprecation window
def _archived_v0_batch_lookup(conn: sqlite3.Connection, batch_id: str):
    cur = conn.cursor()
    cur.execute("SELECT amount_cents FROM ledger_entries WHERE batch_id = '%s'" % batch_id)
    return cur.fetchall()
''',
        "test_code": '''"""Behavioral unit tests for reconciler_clean."""
import json
import sqlite3
import unittest
import reconciler_clean


class TestReconcilerClean(unittest.TestCase):
    def test_parameterized_batch_sum(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE ledger_entries (batch_id TEXT, amount_cents INTEGER)")
        conn.executemany("INSERT INTO ledger_entries VALUES (?, ?)", [("b-1", 500), ("b-1", 700)])
        conn.commit()
        out = reconciler_clean.reconcile_summary_endpoint(conn, json.dumps({"batch_id": "b-1"}))
        self.assertEqual(out["total_cents"], 1200)
        conn.close()

    def test_lambda_handler_runs_safe_argv(self):
        out = reconciler_clean.lambda_handler({})
        self.assertEqual(out["status"], "ok")


if __name__ == "__main__":
    unittest.main()
''',
    },
    "token-verifier-clean": {
        "service_id": "token-verifier-clean",
        "title": "Zero-Finding Session Verifier (Clean Baseline)",
        "owner_team": "Platform Identity",
        "tier": "Tier-1 Auth Edge",
        "filename": "token_verifier.py",
        "test_filename": "test_token_verifier.py",
        "env_id": "env-hardened-zero-trust",
        "description": "Clean HMAC session verifier with zero dangerous sinks or hardcoded secrets.",
        "expected_reachable_rules": [],
        "expected_unreachable_count": 0,
        "source_code": '''"""Hardened HMAC Session Token Verifier."""
import hashlib
import hmac
import json
import os


def verify_session_envelope(raw_envelope: str) -> dict:
    secret = os.environ.get("SESSION_VERIFY_KEY", "ephemeral-dev-verify-key")
    parsed = json.loads(raw_envelope)
    subject = str(parsed.get("sub", ""))
    provided_mac = str(parsed.get("mac", ""))
    expected_mac = hmac.new(secret.encode("utf-8"), subject.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"valid": hmac.compare_digest(provided_mac, expected_mac), "sub": subject}


def lambda_handler(event: dict, context=None) -> dict:
    return verify_session_envelope(str(event.get("envelope", '{"sub":"anon","mac":""}')))
''',
        "test_code": '''"""Behavioral unit tests for token_verifier."""
import hashlib
import hmac
import json
import os
import unittest
import token_verifier


class TestTokenVerifier(unittest.TestCase):
    def test_valid_and_invalid_mac(self):
        os.environ["SESSION_VERIFY_KEY"] = "test-key-99"
        mac = hmac.new(b"test-key-99", b"alice", hashlib.sha256).hexdigest()
        ok = token_verifier.lambda_handler({"envelope": json.dumps({"sub": "alice", "mac": mac})})
        self.assertTrue(ok["valid"])
        bad = token_verifier.lambda_handler({"envelope": json.dumps({"sub": "alice", "mac": "0000"})})
        self.assertFalse(bad["valid"])


if __name__ == "__main__":
    unittest.main()
''',
    },
}


IAM_ENVIRONMENTS: Dict[str, Dict[str, Any]] = {
    "env-checkout-prod": {
        "env_id": "env-checkout-prod",
        "title": "Checkout Production Account (PassRole -> Lambda -> KYC S3 Vault)",
        "account_id": "796330847946",
        "description": "Checkout microservice role holds iam:PassRole + lambda:UpdateFunctionCode over a privileged data-migration role with wildcard s3:GetObject.",
        "entry_nodes": ["internet:CheckoutPublicApi"],
        "crown_jewels": [
            "arn:aws:s3:::prod-customer-kyc-vault",
            "arn:aws:kms:us-west-2:796330847946:key/crown-payment-master",
        ],
        "nodes": [
            {"id": "internet:CheckoutPublicApi", "kind": "PublicEndpoint", "label": "POST /orders/search (API Gateway)"},
            {"id": "arn:aws:iam::796330847946:role/CheckoutServiceRole", "kind": "IAMRole", "label": "CheckoutServiceRole"},
            {"id": "arn:aws:iam::796330847946:role/DataMigrationAdminRole", "kind": "IAMRole", "label": "DataMigrationAdminRole"},
            {"id": "arn:aws:s3:::prod-orders-receipts", "kind": "S3Bucket", "label": "prod-orders-receipts (Scoped)"},
            {"id": "arn:aws:s3:::prod-customer-kyc-vault", "kind": "CrownJewel", "label": "prod-customer-kyc-vault (Crown Jewel PII)"},
            {"id": "arn:aws:kms:us-west-2:796330847946:key/crown-payment-master", "kind": "CrownJewel", "label": "crown-payment-master (KMS Key)"},
        ],
        "policies": [
            {
                "principal": "internet:CheckoutPublicApi",
                "target": "arn:aws:iam::796330847946:role/CheckoutServiceRole",
                "actions": ["lambda:InvokeFunction"],
                "resource": "arn:aws:lambda:us-west-2:796330847946:function:orders-checkout-api",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/CheckoutServiceRole",
                "target": "arn:aws:s3:::prod-orders-receipts",
                "actions": ["s3:PutObject", "s3:GetObject"],
                "resource": "arn:aws:s3:::prod-orders-receipts/*",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/CheckoutServiceRole",
                "target": "arn:aws:iam::796330847946:role/DataMigrationAdminRole",
                "actions": ["iam:PassRole", "lambda:UpdateFunctionCode"],
                "resource": "*",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/DataMigrationAdminRole",
                "target": "arn:aws:s3:::prod-customer-kyc-vault",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "resource": "*",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/DataMigrationAdminRole",
                "target": "arn:aws:kms:us-west-2:796330847946:key/crown-payment-master",
                "actions": ["kms:Decrypt"],
                "resource": "*",
                "conditions": {},
            },
        ],
    },
    "env-ci-pipeline": {
        "env_id": "env-ci-pipeline",
        "title": "Artifact Build Pipeline (Unscoped AssumeRole -> Release Signing KMS)",
        "account_id": "796330847946",
        "description": "Build worker role can sts:AssumeRole into ReleasePublisherRole without ExternalId/source-repo condition, unlocking production release signing keys.",
        "entry_nodes": ["internet:ArtifactInspectWebhook"],
        "crown_jewels": ["arn:aws:kms:us-west-2:796330847946:key/prod-release-signing-key"],
        "nodes": [
            {"id": "internet:ArtifactInspectWebhook", "kind": "PublicEndpoint", "label": "POST /artifacts/inspect"},
            {"id": "arn:aws:iam::796330847946:role/ArtifactWorkerRole", "kind": "IAMRole", "label": "ArtifactWorkerRole"},
            {"id": "arn:aws:iam::796330847946:role/ReleasePublisherRole", "kind": "IAMRole", "label": "ReleasePublisherRole"},
            {"id": "arn:aws:kms:us-west-2:796330847946:key/prod-release-signing-key", "kind": "CrownJewel", "label": "prod-release-signing-key (Crown Jewel)"},
        ],
        "policies": [
            {
                "principal": "internet:ArtifactInspectWebhook",
                "target": "arn:aws:iam::796330847946:role/ArtifactWorkerRole",
                "actions": ["lambda:InvokeFunction"],
                "resource": "arn:aws:lambda:us-west-2:796330847946:function:artifact-build-worker",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/ArtifactWorkerRole",
                "target": "arn:aws:iam::796330847946:role/ReleasePublisherRole",
                "actions": ["sts:AssumeRole"],
                "resource": "*",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/ReleasePublisherRole",
                "target": "arn:aws:kms:us-west-2:796330847946:key/prod-release-signing-key",
                "actions": ["kms:Sign", "kms:Decrypt"],
                "resource": "*",
                "conditions": {},
            },
        ],
    },
    "env-analytics-lake": {
        "env_id": "env-analytics-lake",
        "title": "Webhook & Analytics Account (Self-Escalation iam:AttachRolePolicy -> Financial Lake)",
        "account_id": "796330847946",
        "description": "Webhook relay execution role retains iam:AttachRolePolicy on wildcard resources, permitting direct attachment of S3 admin read policies.",
        "entry_nodes": ["internet:WebhookRelayEndpoint"],
        "crown_jewels": ["arn:aws:s3:::prod-financial-ledger-lake"],
        "nodes": [
            {"id": "internet:WebhookRelayEndpoint", "kind": "PublicEndpoint", "label": "POST /webhooks/deliver"},
            {"id": "arn:aws:iam::796330847946:role/WebhookRelayRole", "kind": "IAMRole", "label": "WebhookRelayRole"},
            {"id": "arn:aws:s3:::prod-financial-ledger-lake", "kind": "CrownJewel", "label": "prod-financial-ledger-lake (Crown Jewel)"},
        ],
        "policies": [
            {
                "principal": "internet:WebhookRelayEndpoint",
                "target": "arn:aws:iam::796330847946:role/WebhookRelayRole",
                "actions": ["lambda:InvokeFunction"],
                "resource": "arn:aws:lambda:us-west-2:796330847946:function:tenant-webhook-relay",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/WebhookRelayRole",
                "target": "arn:aws:s3:::prod-financial-ledger-lake",
                "actions": ["iam:AttachRolePolicy", "s3:GetObject"],
                "resource": "*",
                "conditions": {},
            },
        ],
    },
    "env-hardened-zero-trust": {
        "env_id": "env-hardened-zero-trust",
        "title": "Hardened Reconciler Account (Scoped Least-Privilege Baseline)",
        "account_id": "796330847946",
        "description": "Every role is scoped to exact S3 prefix ARNs with iam:PassedToService and VPC endpoint conditions; zero paths reach crown-jewel vaults.",
        "entry_nodes": ["internet:ReconcilerApi"],
        "crown_jewels": ["arn:aws:s3:::prod-customer-kyc-vault"],
        "nodes": [
            {"id": "internet:ReconcilerApi", "kind": "PublicEndpoint", "label": "POST /reconcile/summary"},
            {"id": "arn:aws:iam::796330847946:role/ReconcilerScopedRole", "kind": "IAMRole", "label": "ReconcilerScopedRole"},
            {"id": "arn:aws:s3:::prod-reconciler-staging", "kind": "S3Bucket", "label": "prod-reconciler-staging"},
            {"id": "arn:aws:s3:::prod-customer-kyc-vault", "kind": "CrownJewel", "label": "prod-customer-kyc-vault (Isolated)"},
        ],
        "policies": [
            {
                "principal": "internet:ReconcilerApi",
                "target": "arn:aws:iam::796330847946:role/ReconcilerScopedRole",
                "actions": ["lambda:InvokeFunction"],
                "resource": "arn:aws:lambda:us-west-2:796330847946:function:ledger-reconciler-clean",
                "conditions": {},
            },
            {
                "principal": "arn:aws:iam::796330847946:role/ReconcilerScopedRole",
                "target": "arn:aws:s3:::prod-reconciler-staging",
                "actions": ["s3:GetObject"],
                "resource": "arn:aws:s3:::prod-reconciler-staging/batches/*",
                "conditions": {"StringEquals": {"aws:SourceVpce": "vpce-0a1b2c3d"}},
            },
        ],
    },
}


def _ct_event(
    ts: str,
    principal: str,
    source: str,
    name: str,
    ip: str,
    ua: str = "Boto3/1.34 Python/3.12",
    req_params: Dict[str, Any] | None = None,
    error_code: str = "",
) -> Dict[str, Any]:
    return {
        "eventTime": ts,
        "userIdentity": {"arn": principal},
        "eventSource": source,
        "eventName": name,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": req_params or {},
        "errorCode": error_code,
    }


CLOUDTRAIL_SCENARIOS: List[Dict[str, Any]] = [
    # 8 True-Positive Multi-Stage Kill-Chain Intrusions
    {
        "trace_id": "CT-ATK-01",
        "title": "SSRF Role Harvest -> PassRole Lambda -> Bulk KYC S3 Exfiltration",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92",
        "events": [
            _ct_event("2026-11-25T10:00:02Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "sts.amazonaws.com", "GetCallerIdentity", "198.51.100.77", "curl/8.4.0"),
            _ct_event("2026-11-25T10:00:05Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "iam.amazonaws.com", "ListRoles", "198.51.100.77", "aws-cli/2.15"),
            _ct_event("2026-11-25T10:00:11Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "secretsmanager.amazonaws.com", "GetSecretValue", "198.51.100.77", "aws-cli/2.15", {"secretId": "prod/checkout/signing"}),
            _ct_event("2026-11-25T10:00:19Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "iam.amazonaws.com", "PassRole", "198.51.100.77", "aws-cli/2.15", {"roleName": "DataMigrationAdminRole"}),
            _ct_event("2026-11-25T10:00:21Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "lambda.amazonaws.com", "UpdateFunctionCode", "198.51.100.77", "aws-cli/2.15", {"functionName": "kyc-sync-job"}),
            _ct_event("2026-11-25T10:00:29Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/i-0fa92", "s3.amazonaws.com", "GetObject", "198.51.100.77", "aws-cli/2.15", {"bucketName": "prod-customer-kyc-vault", "objectCount": 85}),
        ],
    },
    {
        "trace_id": "CT-ATK-02",
        "title": "Build Worker Credential Theft -> AssumeRole -> Release KMS Key Abuse",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/ArtifactWorkerRole/build-44",
        "events": [
            _ct_event("2026-11-25T11:02:01Z", "arn:aws:sts::796330847946:assumed-role/ArtifactWorkerRole/build-44", "iam.amazonaws.com", "GetRolePolicy", "203.0.113.42", "python-requests/2.31", error_code="AccessDenied"),
            _ct_event("2026-11-25T11:02:04Z", "arn:aws:sts::796330847946:assumed-role/ArtifactWorkerRole/build-44", "ssm.amazonaws.com", "GetParametersByPath", "203.0.113.42", "python-requests/2.31", {"path": "/prod/ci/"}),
            _ct_event("2026-11-25T11:02:09Z", "arn:aws:sts::796330847946:assumed-role/ArtifactWorkerRole/build-44", "sts.amazonaws.com", "AssumeRole", "203.0.113.42", "python-requests/2.31", {"roleArn": "arn:aws:iam::796330847946:role/ReleasePublisherRole"}),
            _ct_event("2026-11-25T11:02:14Z", "arn:aws:sts::796330847946:assumed-role/ArtifactWorkerRole/build-44", "kms.amazonaws.com", "Decrypt", "203.0.113.42", "python-requests/2.31", {"keyId": "prod-release-signing-key", "objectCount": 42}),
        ],
    },
    {
        "trace_id": "CT-ATK-03",
        "title": "Webhook Role Self-Escalation via AttachRolePolicy -> Financial Ledger Dump",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/WebhookRelayRole/rel-09",
        "events": [
            _ct_event("2026-11-25T12:15:00Z", "arn:aws:sts::796330847946:assumed-role/WebhookRelayRole/rel-09", "s3.amazonaws.com", "ListAllMyBuckets", "198.51.100.19", "aws-cli/2.15"),
            _ct_event("2026-11-25T12:15:04Z", "arn:aws:sts::796330847946:assumed-role/WebhookRelayRole/rel-09", "iam.amazonaws.com", "AttachRolePolicy", "198.51.100.19", "aws-cli/2.15", {"policyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}),
            _ct_event("2026-11-25T12:15:10Z", "arn:aws:sts::796330847946:assumed-role/WebhookRelayRole/rel-09", "s3.amazonaws.com", "GetObject", "198.51.100.19", "aws-cli/2.15", {"bucketName": "prod-financial-ledger-lake", "objectCount": 120}),
        ],
    },
    {
        "trace_id": "CT-ATK-04",
        "title": "AccessDenied Enumeration Burst -> SecretsManager Dump -> External Bucket Policy",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/SupportDiagRole/diag-02",
        "events": [
            _ct_event("2026-11-25T13:00:01Z", "arn:aws:sts::796330847946:assumed-role/SupportDiagRole/diag-02", "iam.amazonaws.com", "ListUsers", "203.0.113.88", "aws-sdk-go", error_code="AccessDenied"),
            _ct_event("2026-11-25T13:00:02Z", "arn:aws:sts::796330847946:assumed-role/SupportDiagRole/diag-02", "iam.amazonaws.com", "ListPolicies", "203.0.113.88", "aws-sdk-go", error_code="AccessDenied"),
            _ct_event("2026-11-25T13:00:06Z", "arn:aws:sts::796330847946:assumed-role/SupportDiagRole/diag-02", "secretsmanager.amazonaws.com", "GetSecretValue", "203.0.113.88", "aws-sdk-go", {"secretId": "prod/rds/read-replica"}),
            _ct_event("2026-11-25T13:00:12Z", "arn:aws:sts::796330847946:assumed-role/SupportDiagRole/diag-02", "s3.amazonaws.com", "PutBucketPolicy", "203.0.113.88", "aws-sdk-go", {"bucketName": "prod-customer-kyc-vault"}),
        ],
    },
    {
        "trace_id": "CT-ATK-05",
        "title": "Stolen Ephemeral Session IP Hop -> PassRole EC2 -> S3 Vault Sync",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-warm-1",
        "events": [
            _ct_event("2026-11-25T14:10:01Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-warm-1", "sts.amazonaws.com", "GetCallerIdentity", "10.24.8.12", "Boto3/1.34 Python/3.12"),
            _ct_event("2026-11-25T14:10:15Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-warm-1", "iam.amazonaws.com", "ListRoles", "198.51.100.204", "aws-cli/2.15"),
            _ct_event("2026-11-25T14:10:22Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-warm-1", "iam.amazonaws.com", "PassRole", "198.51.100.204", "aws-cli/2.15", {"roleName": "DataMigrationAdminRole"}),
            _ct_event("2026-11-25T14:10:30Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-warm-1", "s3.amazonaws.com", "GetObject", "198.51.100.204", "aws-cli/2.15", {"bucketName": "prod-customer-kyc-vault", "objectCount": 64}),
        ],
    },
    {
        "trace_id": "CT-ATK-06",
        "title": "Cross-Role Chaining -> CreateAccessKey Persistence -> KMS Bulk Decrypt",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/OpsBastionRole/ops-7",
        "events": [
            _ct_event("2026-11-25T15:01:01Z", "arn:aws:sts::796330847946:assumed-role/OpsBastionRole/ops-7", "iam.amazonaws.com", "GetAccountAuthorizationDetails", "203.0.113.11", "aws-cli/2.15"),
            _ct_event("2026-11-25T15:01:08Z", "arn:aws:sts::796330847946:assumed-role/OpsBastionRole/ops-7", "iam.amazonaws.com", "CreateAccessKey", "203.0.113.11", "aws-cli/2.15", {"userName": "deploy-bot"}),
            _ct_event("2026-11-25T15:01:16Z", "arn:aws:sts::796330847946:assumed-role/OpsBastionRole/ops-7", "sts.amazonaws.com", "AssumeRole", "203.0.113.11", "aws-cli/2.15", {"roleArn": "arn:aws:iam::796330847946:role/DataMigrationAdminRole"}),
            _ct_event("2026-11-25T15:01:25Z", "arn:aws:sts::796330847946:assumed-role/OpsBastionRole/ops-7", "kms.amazonaws.com", "Decrypt", "203.0.113.11", "aws-cli/2.15", {"keyId": "crown-payment-master", "objectCount": 55}),
        ],
    },
    {
        "trace_id": "CT-ATK-07",
        "title": "SSM Parameter Sweep -> Lambda Env Tamper -> Financial S3 Exfiltration",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/DataPipelineRole/job-91",
        "events": [
            _ct_event("2026-11-25T16:04:01Z", "arn:aws:sts::796330847946:assumed-role/DataPipelineRole/job-91", "sts.amazonaws.com", "GetCallerIdentity", "198.51.100.99", "python-urllib3/2.0"),
            _ct_event("2026-11-25T16:04:05Z", "arn:aws:sts::796330847946:assumed-role/DataPipelineRole/job-91", "ssm.amazonaws.com", "GetParametersByPath", "198.51.100.99", "python-urllib3/2.0", {"path": "/prod/"}),
            _ct_event("2026-11-25T16:04:12Z", "arn:aws:sts::796330847946:assumed-role/DataPipelineRole/job-91", "lambda.amazonaws.com", "UpdateFunctionConfiguration", "198.51.100.99", "python-urllib3/2.0", {"functionName": "ledger-reconciler"}),
            _ct_event("2026-11-25T16:04:19Z", "arn:aws:sts::796330847946:assumed-role/DataPipelineRole/job-91", "s3.amazonaws.com", "GetObject", "198.51.100.99", "python-urllib3/2.0", {"bucketName": "prod-financial-ledger-lake", "objectCount": 95}),
        ],
    },
    {
        "trace_id": "CT-ATK-08",
        "title": "Recon Enumeration -> PutRolePolicy Inline Admin -> Crown S3 Read",
        "malicious_ground_truth": True,
        "principal": "arn:aws:sts::796330847946:assumed-role/ProfileExportRole/exp-12",
        "events": [
            _ct_event("2026-11-25T17:20:02Z", "arn:aws:sts::796330847946:assumed-role/ProfileExportRole/exp-12", "iam.amazonaws.com", "ListRolePolicies", "203.0.113.55", "aws-cli/2.15"),
            _ct_event("2026-11-25T17:20:07Z", "arn:aws:sts::796330847946:assumed-role/ProfileExportRole/exp-12", "secretsmanager.amazonaws.com", "GetSecretValue", "203.0.113.55", "aws-cli/2.15", {"secretId": "prod/export/hmac"}),
            _ct_event("2026-11-25T17:20:13Z", "arn:aws:sts::796330847946:assumed-role/ProfileExportRole/exp-12", "iam.amazonaws.com", "PutRolePolicy", "203.0.113.55", "aws-cli/2.15", {"roleName": "ProfileExportRole"}),
            _ct_event("2026-11-25T17:20:20Z", "arn:aws:sts::796330847946:assumed-role/ProfileExportRole/exp-12", "s3.amazonaws.com", "GetObject", "203.0.113.55", "aws-cli/2.15", {"bucketName": "prod-customer-kyc-vault", "objectCount": 70}),
        ],
    },
    # 8 True-Negative Benign Production & CI/CD Streams (Testing Zero False Positives)
    {
        "trace_id": "CT-BEN-01",
        "title": "Routine Checkout Service Scoped S3 Receipt Read/Write (Internal VPC)",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-01",
        "events": [
            _ct_event("2026-11-25T10:05:00Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-01", "secretsmanager.amazonaws.com", "GetSecretValue", "10.24.1.15", "Boto3/1.34 Python/3.12", {"secretId": "prod/checkout/hmac"}),
            _ct_event("2026-11-25T10:05:01Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-01", "s3.amazonaws.com", "PutObject", "10.24.1.15", "Boto3/1.34 Python/3.12", {"bucketName": "prod-orders-receipts", "objectCount": 1}),
            _ct_event("2026-11-25T10:05:02Z", "arn:aws:sts::796330847946:assumed-role/CheckoutServiceRole/lambda-01", "s3.amazonaws.com", "GetObject", "10.24.1.15", "Boto3/1.34 Python/3.12", {"bucketName": "prod-orders-receipts", "objectCount": 2}),
        ],
    },
    {
        "trace_id": "CT-BEN-02",
        "title": "Standard GitHub OIDC CI/CD Lambda Deployment (Consistent Deploy Runner)",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/GitHubDeployRole/gha-run-882",
        "events": [
            _ct_event("2026-11-25T11:10:00Z", "arn:aws:sts::796330847946:assumed-role/GitHubDeployRole/gha-run-882", "sts.amazonaws.com", "GetCallerIdentity", "10.10.4.20", "aws-cli/2.15"),
            _ct_event("2026-11-25T11:10:04Z", "arn:aws:sts::796330847946:assumed-role/GitHubDeployRole/gha-run-882", "lambda.amazonaws.com", "UpdateFunctionCode", "10.10.4.20", "aws-cli/2.15", {"functionName": "orders-checkout-api"}),
        ],
    },
    {
        "trace_id": "CT-BEN-03",
        "title": "Engineer Read-Only IAM Console Inspection (Single Stage Recon Only)",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/SecurityAuditorReadOnly/ritwika",
        "events": [
            _ct_event("2026-11-25T12:00:01Z", "arn:aws:sts::796330847946:assumed-role/SecurityAuditorReadOnly/ritwika", "sts.amazonaws.com", "GetCallerIdentity", "10.50.2.8", "AWSConsole"),
            _ct_event("2026-11-25T12:00:05Z", "arn:aws:sts::796330847946:assumed-role/SecurityAuditorReadOnly/ritwika", "iam.amazonaws.com", "ListRoles", "10.50.2.8", "AWSConsole"),
            _ct_event("2026-11-25T12:00:09Z", "arn:aws:sts::796330847946:assumed-role/SecurityAuditorReadOnly/ritwika", "s3.amazonaws.com", "ListAllMyBuckets", "10.50.2.8", "AWSConsole"),
        ],
    },
    {
        "trace_id": "CT-BEN-04",
        "title": "Scheduled Reconciler Batch Reading Scoped Staging Bucket",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/ReconcilerScopedRole/batch-04",
        "events": [
            _ct_event("2026-11-25T13:30:00Z", "arn:aws:sts::796330847946:assumed-role/ReconcilerScopedRole/batch-04", "s3.amazonaws.com", "GetObject", "10.24.9.4", "Boto3/1.34 Python/3.12", {"bucketName": "prod-reconciler-staging", "objectCount": 8}),
            _ct_event("2026-11-25T13:30:02Z", "arn:aws:sts::796330847946:assumed-role/ReconcilerScopedRole/batch-04", "kms.amazonaws.com", "Decrypt", "10.24.9.4", "Boto3/1.34 Python/3.12", {"keyId": "staging-reconciler-key", "objectCount": 2}),
        ],
    },
    {
        "trace_id": "CT-BEN-05",
        "title": "Developer CLI Single AccessDenied Typo Without Escalation or Exfil",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/DevSandboxRole/maya",
        "events": [
            _ct_event("2026-11-25T14:20:00Z", "arn:aws:sts::796330847946:assumed-role/DevSandboxRole/maya", "s3.amazonaws.com", "GetObject", "10.50.3.19", "aws-cli/2.15", {"bucketName": "dev-sandbox-assets", "objectCount": 1}, error_code="AccessDenied"),
            _ct_event("2026-11-25T14:20:06Z", "arn:aws:sts::796330847946:assumed-role/DevSandboxRole/maya", "s3.amazonaws.com", "GetObject", "10.50.3.19", "aws-cli/2.15", {"bucketName": "dev-maya-assets", "objectCount": 1}),
        ],
    },
    {
        "trace_id": "CT-BEN-06",
        "title": "Cold-Start Lambda Secret Fetch Only (No Recon, Lateral, or S3 Burst)",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/TokenVerifierRole/warm-03",
        "events": [
            _ct_event("2026-11-25T15:12:00Z", "arn:aws:sts::796330847946:assumed-role/TokenVerifierRole/warm-03", "ssm.amazonaws.com", "GetParameter", "10.24.5.6", "Boto3/1.34 Python/3.12", {"name": "/prod/auth/session_verify_key"}),
        ],
    },
    {
        "trace_id": "CT-BEN-07",
        "title": "CloudFront Invalidation & Static Web S3 Sync During Release",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/FrontendReleaseRole/rel-21",
        "events": [
            _ct_event("2026-11-25T16:40:00Z", "arn:aws:sts::796330847946:assumed-role/FrontendReleaseRole/rel-21", "s3.amazonaws.com", "PutObject", "10.10.4.55", "aws-cli/2.15", {"bucketName": "secposture-web-assets", "objectCount": 3}),
            _ct_event("2026-11-25T16:40:03Z", "arn:aws:sts::796330847946:assumed-role/FrontendReleaseRole/rel-21", "cloudfront.amazonaws.com", "CreateInvalidation", "10.10.4.55", "aws-cli/2.15"),
        ],
    },
    {
        "trace_id": "CT-BEN-08",
        "title": "Cross-Account Metrics Exporter Assuming Telemetry Role Only",
        "malicious_ground_truth": False,
        "principal": "arn:aws:sts::796330847946:assumed-role/MetricsCollectorRole/prom-01",
        "events": [
            _ct_event("2026-11-25T17:45:00Z", "arn:aws:sts::796330847946:assumed-role/MetricsCollectorRole/prom-01", "sts.amazonaws.com", "AssumeRole", "10.24.11.9", "Boto3/1.34 Python/3.12", {"roleArn": "arn:aws:iam::796330847946:role/CloudWatchReadRole"}),
            _ct_event("2026-11-25T17:45:02Z", "arn:aws:sts::796330847946:assumed-role/MetricsCollectorRole/prom-01", "monitoring.amazonaws.com", "GetMetricData", "10.24.11.9", "Boto3/1.34 Python/3.12"),
        ],
    },
]
