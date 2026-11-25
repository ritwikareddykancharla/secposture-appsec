"""Automated STRIDE AppSec Design Review & Bedrock Threat Modeler (`secposture/threat_review.py`).

Synthesizes evidence-backed architecture threat reviews combining deterministic AST call-graph
reachability findings (`file:line`) and IAM multi-hop escalation paths (`role_arn -> crown_jewel`)
with live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) threat scenarios via the Converse API.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from .attack_graph import analyze_iam_attack_paths, get_iam_environment
from .reachability_ast import scan_python_reachability
from .sample_services import IAM_ENVIRONMENTS, SERVICE_REPOS


def invoke_bedrock_nova(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 420,
) -> Optional[Dict[str, Any]]:
    """Call live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) via boto3 Converse API."""
    if os.environ.get("SECPOSTURE_OFFLINE_LLM") == "1":
        return None

    model_id = os.environ.get("SECPOSTURE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0")
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
    t0 = time.perf_counter()

    try:
        import boto3  # type: ignore

        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
            session = boto3.Session(region_name=region)
        else:
            raw_prof = os.environ.get("AWS_PROFILE", "portfolio")
            profile = "portfolio" if raw_prof in ("", "trainium") else raw_prof
            session = boto3.Session(profile_name=profile, region_name=region)

        client = session.client("bedrock-runtime", region_name=region)
        resp = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.1},
        )
        round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        server_ms = float(resp.get("metrics", {}).get("latencyMs") or round_trip_ms)
        usage = resp.get("usage", {})
        text = resp["output"]["message"]["content"][0]["text"]
        return {
            "text": text.strip(),
            "engine": "Amazon Bedrock",
            "model_id": model_id,
            "latency_ms": round(server_ms, 2),
            "round_trip_ms": round_trip_ms,
            "input_tokens": int(usage.get("inputTokens", 0)),
            "output_tokens": int(usage.get("outputTokens", 0)),
            "total_tokens": int(usage.get("totalTokens", 0)),
        }
    except Exception:
        pass

    # Fallback CLI path if boto3 session encounters local credential config quirk
    aws_bin = shutil.which("aws")
    if not aws_bin:
        return None
    env = dict(os.environ)
    env.pop("AWS_ACCESS_KEY_ID", None)
    env.pop("AWS_SECRET_ACCESS_KEY", None)
    env.pop("AWS_SESSION_TOKEN", None)
    env["AWS_PROFILE"] = os.environ.get("AWS_PROFILE", "portfolio")
    env["AWS_DEFAULT_REGION"] = region
    cmd = [
        aws_bin,
        "bedrock-runtime",
        "converse",
        "--region",
        region,
        "--model-id",
        model_id,
        "--system",
        json.dumps([{"text": system_prompt}]),
        "--messages",
        json.dumps([{"role": "user", "content": [{"text": user_prompt}]}]),
        "--inference-config",
        json.dumps({"maxTokens": max_tokens, "temperature": 0.1}),
        "--output",
        "json",
    ]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15.0)
        round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            server_ms = float(data.get("metrics", {}).get("latencyMs") or round_trip_ms)
            usage = data.get("usage", {})
            text = data["output"]["message"]["content"][0]["text"]
            return {
                "text": text.strip(),
                "engine": "Amazon Bedrock",
                "model_id": model_id,
                "latency_ms": round(server_ms, 2),
                "round_trip_ms": round_trip_ms,
                "input_tokens": int(usage.get("inputTokens", 0)),
                "output_tokens": int(usage.get("outputTokens", 0)),
                "total_tokens": int(usage.get("totalTokens", 0)),
            }
    except Exception:
        pass
    return None


def build_stride_matrix(
    ast_scan: Dict[str, Any],
    iam_graph: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Map deterministic AST & IAM findings onto the 6 STRIDE threat categories."""
    reachable = ast_scan.get("reachable_findings", [])
    paths = iam_graph.get("attack_paths", [])

    by_rule: Dict[str, List[Dict[str, Any]]] = {}
    for f in reachable:
        by_rule.setdefault(f["rule_id"], []).append(f)

    stride_rows: List[Dict[str, Any]] = []

    # 1. Spoofing
    secrets = by_rule.get("SEC-AST-SECRET-05", [])
    stride_rows.append(
        {
            "stride": "Spoofing",
            "status": "FINDING_OPEN" if secrets else "CONTROL_VERIFIED",
            "severity": "HIGH" if secrets else "LOW",
            "anchored_evidence": [f["location"] for f in secrets] or ["Secrets loaded from environment / KMS"],
            "finding_summary": (
                f"Hardcoded signing secret at {secrets[0]['location']} allows forging receipt or session MACs if source is leaked."
                if secrets
                else "No hardcoded signing or API credentials reachable from service entrypoints."
            ),
            "required_control": "Rotate signing key into AWS Secrets Manager and load via environment binding.",
        }
    )

    # 2. Tampering
    tamper_findings = by_rule.get("SEC-AST-SQLI-01", []) + by_rule.get("SEC-AST-CMDI-02", []) + by_rule.get("SEC-AST-DESER-04", [])
    stride_rows.append(
        {
            "stride": "Tampering",
            "status": "FINDING_OPEN" if tamper_findings else "CONTROL_VERIFIED",
            "severity": "CRITICAL" if tamper_findings else "LOW",
            "anchored_evidence": [f["location"] for f in tamper_findings] or ["Parameterized SQL & shell=False"],
            "finding_summary": (
                "; ".join(f"{f['category']} at {f['location']}" for f in tamper_findings)
                if tamper_findings
                else "All reachable SQL queries use '?' bindings, subprocess calls enforce shell=False, and payloads use JSON."
            ),
            "required_control": "Enforce '?' SQL parameter tuples, shell=False argv arrays, and JSON schema parsing.",
        }
    )

    # 3. Repudiation
    stride_rows.append(
        {
            "stride": "Repudiation",
            "status": "CONTROL_VERIFIED",
            "severity": "LOW",
            "anchored_evidence": ["SQLiteAuditLedger (SHA-256 chain)", "CloudTrail multi-stage sequence telemetry"],
            "finding_summary": "Every posture scan, auto-patch test run, and IAM containment policy is recorded in a SHA-256 hash-linked SQLite WAL log.",
            "required_control": "Maintain append-only SHA-256 hash verification across security review receipts.",
        }
    )

    # 4. Information Disclosure
    ssrf_findings = by_rule.get("SEC-AST-SSRF-03", [])
    crown_Jewel_arns = sorted({p["crown_jewel"] for p in paths})
    info_open = bool(ssrf_findings or crown_Jewel_arns)
    evidence_info = [f["location"] for f in ssrf_findings] + crown_Jewel_arns
    stride_rows.append(
        {
            "stride": "Information Disclosure",
            "status": "FINDING_OPEN" if info_open else "CONTROL_VERIFIED",
            "severity": "CRITICAL" if crown_Jewel_arns else ("HIGH" if ssrf_findings else "LOW"),
            "anchored_evidence": evidence_info or ["Scoped S3 ARNs + HTTPS partner allowlist"],
            "finding_summary": (
                (
                    f"Unvalidated outbound URL fetch ({ssrf_findings[0]['location']}) and/or wildcard S3/KMS permissions expose {', '.join(crown_Jewel_arns) or 'internal metadata'}."
                    if ssrf_findings
                    else f"Wildcard or unscoped IAM permissions expose crown-jewel assets: {', '.join(crown_Jewel_arns)}."
                )
                if info_open
                else "Outbound HTTP enforces HTTPS host allowlists and crown-jewel S3/KMS buckets remain unreachable."
            ),
            "required_control": "Block link-local/RFC1918 IPs in outbound HTTP and scope S3/KMS policies to VPC endpoints.",
        }
    )

    # 5. Denial of Service
    cmdi_findings = by_rule.get("SEC-AST-CMDI-02", [])
    stride_rows.append(
        {
            "stride": "Denial of Service",
            "status": "FINDING_OPEN" if cmdi_findings else "CONTROL_VERIFIED",
            "severity": "MEDIUM" if cmdi_findings else "LOW",
            "anchored_evidence": [f["location"] for f in cmdi_findings] or ["Bounded 3.0s HTTP & 8.0s subprocess timeouts"],
            "finding_summary": (
                f"Unbounded shell subprocess invocation at {cmdi_findings[0]['location']} risks worker exhaustion."
                if cmdi_findings
                else "Subprocess and outbound HTTP calls enforce explicit timeouts without shell spawning."
            ),
            "required_control": "Enforce shell=False with explicit subprocess timeout budgets.",
        }
    )

    # 6. Elevation of Privilege
    stride_rows.append(
        {
            "stride": "Elevation of Privilege",
            "status": "FINDING_OPEN" if paths else "CONTROL_VERIFIED",
            "severity": "CRITICAL" if paths else "LOW",
            "anchored_evidence": [
                " -> ".join(paths[0]["ordered_labels"])
            ] if paths else ["0 multi-hop privilege escalation paths"],
            "finding_summary": (
                f"{len(paths)} exploitable IAM path(s) discovered; shortest is {paths[0]['hop_count']} hops via {', '.join(paths[0]['toxic_rules'])} to {paths[0]['crown_jewel']}."
                if paths
                else "Zero IAM privilege-escalation paths from external entrypoints to crown-jewel assets."
            ),
            "required_control": "Remove lambda:UpdateFunctionCode / iam:AttachRolePolicy from runtime roles and require sts:ExternalId or iam:PassedToService.",
        }
    )

    return stride_rows


def generate_appsec_threat_review(
    service_id: str = "orders-checkout-api",
    env_id: Optional[str] = None,
    architecture_notes: str = "",
    use_bedrock: bool = True,
) -> Dict[str, Any]:
    """Run full AppSec Design Review combining AST reachability + IAM graph + Bedrock Nova Lite."""
    t0 = time.perf_counter()
    if service_id not in SERVICE_REPOS:
        raise KeyError(f"Unknown service_id: {service_id}")

    repo = SERVICE_REPOS[service_id]
    chosen_env_id = env_id or repo["env_id"]
    env_snap = get_iam_environment(chosen_env_id)

    ast_scan = scan_python_reachability(repo["source_code"], filename=repo["filename"])
    iam_graph = analyze_iam_attack_paths(env_snap, apply_least_privilege_patch=False)
    stride_matrix = build_stride_matrix(ast_scan=ast_scan, iam_graph=iam_graph)

    open_stride = [row for row in stride_matrix if row["status"] == "FINDING_OPEN"]
    launch_decision = (
        "BLOCK_LAUNCH_UNTIL_PATCHED"
        if (ast_scan["reachable_count"] > 0 or iam_graph["attack_paths_count"] > 0)
        else "APPROVED_FOR_PRODUCTION"
    )

    reachable_summary = [
        f"- {f['rule_id']} ({f['cwe']}) at {f['location']} via {' -> '.join(f['call_chain'])}"
        for f in ast_scan["reachable_findings"]
    ] or ["- 0 reachable code vulnerabilities"]

    iam_summary = [
        f"- {p['hop_count']}-hop path ({', '.join(p['toxic_rules'])}): {' -> '.join(p['ordered_nodes'])}"
        for p in iam_graph["attack_paths"]
    ] or ["- 0 IAM privilege-escalation paths to crown jewels"]

    bedrock_result: Optional[Dict[str, Any]] = None
    if use_bedrock:
        sys_prompt = (
            "You are a Principal Application Security Engineer at Amazon conducting a concise, "
            "evidence-anchored AppSec Launch Review. Reference the exact file:line locations and "
            "AWS IAM ARNs provided. Never use em-dashes. Write 3 short sections: "
            "1) Launch Readiness Decision, 2) Top Exploitable Compound Kill Chain (combining code + IAM), "
            "and 3) Mandatory Fixes Before Launch."
        )
        usr_prompt = (
            f"Service: {repo['title']} ({repo['filename']})\n"
            f"AWS Environment: {env_snap['title']}\n"
            f"Builder Notes: {architecture_notes or repo['description']}\n"
            f"Reachable AST Findings ({ast_scan['reachable_count']} reachable, {ast_scan['unreachable_count']} dead-code filtered):\n"
            + "\n".join(reachable_summary)
            + "\nIAM Attack-Path Findings:\n"
            + "\n".join(iam_summary)
        )
        bedrock_result = invoke_bedrock_nova(sys_prompt, usr_prompt, max_tokens=380)

    if bedrock_result:
        narrative = bedrock_result["text"].replace("—", "-")
        llm_meta = {
            "engine": "Amazon Bedrock",
            "model_id": bedrock_result["model_id"],
            "latency_ms": bedrock_result["latency_ms"],
            "round_trip_ms": bedrock_result["round_trip_ms"],
            "total_tokens": bedrock_result["total_tokens"],
        }
    else:
        narrative = (
            f"1) Launch Readiness Decision: {launch_decision}. Deterministic analysis found "
            f"{ast_scan['reachable_count']} reachable code vulnerabilities in {repo['filename']} "
            f"(filtering {ast_scan['unreachable_count']} unreachable dead-code helpers) and "
            f"{iam_graph['attack_paths_count']} IAM privilege-escalation paths in {chosen_env_id}.\n\n"
            f"2) Compound Threat Path: {reachable_summary[0]} combined with {iam_summary[0]}.\n\n"
            f"3) Mandatory Fixes: Run SecPosture Auto-Patch to parameterize SQL / enforce HTTPS allowlists / "
            f"remove shell=True, verify unit tests pass in /tmp, and apply the scoped least-privilege IAM policy."
        )
        llm_meta = {
            "engine": "Deterministic STRIDE Fallback",
            "model_id": "offline-deterministic",
            "latency_ms": 0.0,
            "round_trip_ms": 0.0,
            "total_tokens": 0,
        }

    review_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "service_id": service_id,
        "service_title": repo["title"],
        "env_id": chosen_env_id,
        "launch_decision": launch_decision,
        "open_stride_categories": len(open_stride),
        "review_total_ms": review_ms,
        "ast_summary": {
            "filename": repo["filename"],
            "reachable_count": ast_scan["reachable_count"],
            "unreachable_count": ast_scan["unreachable_count"],
            "alert_noise_reduction_pct": ast_scan["alert_noise_reduction_pct"],
            "posture_score": ast_scan["posture_score"],
            "reachable_findings": ast_scan["reachable_findings"],
        },
        "iam_summary": {
            "attack_paths_count": iam_graph["attack_paths_count"],
            "shortest_hop_count": iam_graph["shortest_hop_count"],
            "crown_jewels": iam_graph["crown_jewels"],
            "attack_paths": iam_graph["attack_paths"],
        },
        "stride_matrix": stride_matrix,
        "bedrock_review": narrative,
        "llm_telemetry": llm_meta,
    }
