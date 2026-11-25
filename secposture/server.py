"""HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for SecPosture (`secposture/server.py`)."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .attack_graph import (
    analyze_iam_attack_paths,
    detect_cloudtrail_kill_chain,
    get_iam_environment,
)
from .audit_ledger import SQLiteAuditLedger
from .autopatch_loop import run_closed_loop_autopatch
from .reachability_ast import scan_python_reachability
from .sample_services import CLOUDTRAIL_SCENARIOS, IAM_ENVIRONMENTS, SERVICE_REPOS
from .threat_review import generate_appsec_threat_review, invoke_bedrock_nova

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCHMARK_JSON_PATH = ROOT_DIR / "benchmarks" / "latest_results.json"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


class SecPostureControlPlane:
    """Stateful Serverless Control Plane coordinating AST Scans, Attack Graphs, Auto-Patching & Audit Ledger."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.ledger = SQLiteAuditLedger(db_path=db_path)
        self._seed_initial_audit_row()

    def _seed_initial_audit_row(self) -> None:
        if not self.ledger.list_recent(limit=1):
            scan = scan_python_reachability(
                SERVICE_REPOS["orders-checkout-api"]["source_code"],
                filename="orders_service.py",
            )
            self.ledger.append_event(
                category="AST_REACHABILITY_SCAN",
                target_id="orders-checkout-api",
                verdict=scan["posture_status"],
                duration_ms=scan["scan_ms"],
                details={
                    "reachable_count": scan["reachable_count"],
                    "unreachable_count": scan["unreachable_count"],
                    "posture_score": scan["posture_score"],
                },
            )

    def load_benchmarks(self) -> Dict[str, Any]:
        if BENCHMARK_JSON_PATH.is_file():
            try:
                return json.loads(BENCHMARK_JSON_PATH.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def get_state_snapshot(self) -> Dict[str, Any]:
        services_catalog = []
        for sid, repo in SERVICE_REPOS.items():
            scan = scan_python_reachability(repo["source_code"], filename=repo["filename"])
            services_catalog.append(
                {
                    "service_id": sid,
                    "title": repo["title"],
                    "owner_team": repo["owner_team"],
                    "tier": repo["tier"],
                    "filename": repo["filename"],
                    "test_filename": repo["test_filename"],
                    "env_id": repo["env_id"],
                    "description": repo["description"],
                    "source_code": repo["source_code"],
                    "reachable_count": scan["reachable_count"],
                    "unreachable_count": scan["unreachable_count"],
                    "posture_score": scan["posture_score"],
                    "posture_status": scan["posture_status"],
                }
            )

        iam_catalog = [
            {
                "env_id": eid,
                "title": env["title"],
                "description": env["description"],
                "crown_jewels": env["crown_jewels"],
                "nodes_count": len(env["nodes"]),
            }
            for eid, env in IAM_ENVIRONMENTS.items()
        ]

        ct_catalog = [
            {
                "trace_id": sc["trace_id"],
                "title": sc["title"],
                "malicious_ground_truth": sc["malicious_ground_truth"],
                "events_count": len(sc["events"]),
            }
            for sc in CLOUDTRAIL_SCENARIOS[:6] + CLOUDTRAIL_SCENARIOS[8:11]
        ]

        return {
            "services": services_catalog,
            "iam_environments": iam_catalog,
            "cloudtrail_traces": ct_catalog,
            "audit_events": self.ledger.list_recent(limit=20),
            "audit_chain": self.ledger.verify_chain_integrity(),
            "benchmarks": self.load_benchmarks(),
        }

    def scan_reachability(self, body: Dict[str, Any]) -> Dict[str, Any]:
        service_id = str(body.get("service_id") or "").strip()
        custom_source = body.get("source_code")
        if custom_source and str(custom_source).strip():
            filename = str(body.get("filename") or "custom_service.py").strip()
            res = scan_python_reachability(str(custom_source), filename=filename)
            res["service_id"] = service_id or "custom-snippet"
        else:
            sid = service_id or "orders-checkout-api"
            if sid not in SERVICE_REPOS:
                raise KeyError(f"Unknown service_id: {sid}")
            repo = SERVICE_REPOS[sid]
            res = scan_python_reachability(repo["source_code"], filename=repo["filename"])
            res["service_id"] = sid
            res["service_title"] = repo["title"]

        receipt = self.ledger.append_event(
            category="AST_REACHABILITY_SCAN",
            target_id=res["service_id"],
            verdict=res["posture_status"],
            duration_ms=res["scan_ms"],
            details={
                "reachable_count": res["reachable_count"],
                "unreachable_count": res["unreachable_count"],
                "alert_noise_reduction_pct": res["alert_noise_reduction_pct"],
            },
        )
        res["audit_receipt"] = receipt
        return res

    def analyze_graph_and_killchain(self, body: Dict[str, Any]) -> Dict[str, Any]:
        env_id = str(body.get("env_id") or "env-checkout-prod").strip()
        apply_patch = bool(body.get("apply_least_privilege_patch", False))
        trace_id = str(body.get("trace_id") or "CT-ATK-01").strip()

        env_snap = get_iam_environment(env_id)
        graph_out = analyze_iam_attack_paths(env_snap, apply_least_privilege_patch=apply_patch)

        trace_obj = next((t for t in CLOUDTRAIL_SCENARIOS if t["trace_id"] == trace_id), CLOUDTRAIL_SCENARIOS[0])
        if isinstance(body.get("custom_events"), list) and body["custom_events"]:
            trace_obj = {
                "trace_id": "CT-CUSTOM",
                "title": "Custom CloudTrail Event Sequence",
                "events": body["custom_events"],
            }
        killchain_out = detect_cloudtrail_kill_chain(trace_obj)

        receipt = self.ledger.append_event(
            category="IAM_GRAPH_AND_KILLCHAIN",
            target_id=f"{env_id}:{trace_obj['trace_id']}",
            verdict="ALERT_OR_PATH_OPEN" if (graph_out["attack_paths_count"] > 0 or killchain_out["incident_detected"]) else "CLEAR",
            duration_ms=round(graph_out["solve_ms"] + killchain_out["detect_ms"], 3),
            details={
                "attack_paths_count": graph_out["attack_paths_count"],
                "patched_mode": apply_patch,
                "incident_detected": killchain_out["incident_detected"],
                "anomaly_score": killchain_out["anomaly_score"],
            },
        )
        return {
            "iam_graph": graph_out,
            "cloudtrail_detection": killchain_out,
            "audit_receipt": receipt,
        }

    def patch_and_verify(self, body: Dict[str, Any]) -> Dict[str, Any]:
        service_id = body.get("service_id")
        source_code = body.get("source_code")
        include_bedrock_cr = bool(body.get("include_bedrock_cr", False))

        sid = str(service_id).strip() if service_id else ("orders-checkout-api" if not source_code else None)
        out = run_closed_loop_autopatch(
            service_id=sid,
            source_code=str(source_code) if source_code else None,
            filename=str(body.get("filename") or "custom_service.py"),
        )

        cr_summary = None
        if include_bedrock_cr and out["unified_diff"]:
            llm = invoke_bedrock_nova(
                system_prompt=(
                    "You are an Amazon Security Automation Engineer writing a concise 3-bullet "
                    "Code Review (CR) description for an automated security patch. Never use em-dashes."
                ),
                user_prompt=(
                    f"Service: {out['service_id']} ({out['filename']})\n"
                    f"Patch Actions: {out['patch_actions']}\n"
                    f"Verification Gates: {out['gates']}\n"
                    f"Unified Diff:\n{out['unified_diff'][:1800]}"
                ),
                max_tokens=240,
            )
            if llm:
                cr_summary = {
                    "text": llm["text"].replace("—", "-"),
                    "latency_ms": llm["latency_ms"],
                    "total_tokens": llm["total_tokens"],
                    "model_id": llm["model_id"],
                }

        out["bedrock_cr_summary"] = cr_summary
        receipt = self.ledger.append_event(
            category="CLOSED_LOOP_AUTOPATCH",
            target_id=out["service_id"],
            verdict=out["status"],
            duration_ms=out["total_loop_ms"],
            details=out["gates"],
        )
        out["audit_receipt"] = receipt
        return out

    def run_threat_review(self, body: Dict[str, Any]) -> Dict[str, Any]:
        service_id = str(body.get("service_id") or "orders-checkout-api").strip()
        env_id = body.get("env_id")
        notes = str(body.get("architecture_notes") or "").strip()
        use_bedrock = bool(body.get("use_bedrock", True))

        out = generate_appsec_threat_review(
            service_id=service_id,
            env_id=str(env_id).strip() if env_id else None,
            architecture_notes=notes,
            use_bedrock=use_bedrock,
        )
        receipt = self.ledger.append_event(
            category="STRIDE_THREAT_REVIEW",
            target_id=f"{service_id}:{out['env_id']}",
            verdict=out["launch_decision"],
            duration_ms=out["review_total_ms"],
            details={
                "open_stride_categories": out["open_stride_categories"],
                "llm_engine": out["llm_telemetry"]["engine"],
                "tokens": out["llm_telemetry"]["total_tokens"],
            },
        )
        out["audit_receipt"] = receipt
        return out

    def reset(self) -> None:
        self.ledger.reset()
        self._seed_initial_audit_row()


CONTROL_PLANE = SecPostureControlPlane()


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Pure router shared by local HTTP server and AWS Lambda `/api/*` origin behind CloudFront."""
    try:
        if method == "GET" and path == "/api/health":
            chain = CONTROL_PLANE.ledger.verify_chain_integrity()
            return 200, {
                "status": "ok",
                "service": "secposture-appsec",
                "delivery": os.environ.get("SECPOSTURE_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2")),
                "bedrock_model": os.environ.get("SECPOSTURE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
                "python_version": platform.python_version(),
                "request_id": request_id,
                "services_loaded": len(SERVICE_REPOS),
                "iam_environments_loaded": len(IAM_ENVIRONMENTS),
                "sqlite_audit_chain_valid": chain["valid"],
                "sqlite_audit_rows": chain["checked_rows"],
            }

        if method == "GET" and path == "/api/state":
            snap = CONTROL_PLANE.get_state_snapshot()
            snap["request_id"] = request_id
            return 200, snap

        if method == "GET" and path == "/api/benchmarks":
            bench = CONTROL_PLANE.load_benchmarks()
            return 200, bench

        if method == "POST" and path == "/api/scan/reachability":
            out = CONTROL_PLANE.scan_reachability(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/graph/attack-paths":
            out = CONTROL_PLANE.analyze_graph_and_killchain(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/patch/verify":
            out = CONTROL_PLANE.patch_and_verify(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/threat-review":
            out = CONTROL_PLANE.run_threat_review(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/reset":
            CONTROL_PLANE.reset()
            return 200, {
                "status": "reset_complete",
                "service": "secposture-appsec",
                "request_id": request_id,
            }

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except KeyError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except SyntaxError as exc:
        return 400, {"error": f"Python syntax error in scanned source: {exc}"}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None}
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalSecPostureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3099) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalSecPostureHandler)
    print(f"SecPosture AppSec Workbench running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3099"))
    run_local_server(port=port_num)
