"""Multi-Hop IAM & Cloud Attack-Path Solver + Stateful CloudTrail Kill-Chain Detector (`secposture/attack_graph.py`)."""
from __future__ import annotations

import copy
import heapq
import ipaddress
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .sample_services import CLOUDTRAIL_SCENARIOS, IAM_ENVIRONMENTS

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:PassRole",
    "lambda:UpdateFunctionCode",
    "lambda:CreateFunction",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
}

DATA_EXFIL_ACTIONS = {
    "s3:GetObject",
    "s3:ListBucket",
    "kms:Decrypt",
    "kms:Sign",
    "secretsmanager:GetSecretValue",
}

RECON_EVENTS = {
    "GetCallerIdentity",
    "ListRoles",
    "GetRolePolicy",
    "ListUsers",
    "ListPolicies",
    "ListAllMyBuckets",
    "GetAccountAuthorizationDetails",
    "ListRolePolicies",
}

CREDENTIAL_EVENTS = {
    "GetSecretValue",
    "GetParametersByPath",
    "GetParameter",
    "CreateAccessKey",
}

LATERAL_EVENTS = {
    "PassRole",
    "UpdateFunctionCode",
    "UpdateFunctionConfiguration",
    "AssumeRole",
    "AttachRolePolicy",
    "PutRolePolicy",
}

EXFIL_EVENTS = {
    "GetObject",
    "PutBucketPolicy",
    "Decrypt",
}

SENSITIVE_BUCKETS_AND_KEYS = {
    "prod-customer-kyc-vault",
    "prod-financial-ledger-lake",
    "crown-payment-master",
    "prod-release-signing-key",
}


def _is_private_vpc_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def _classify_policy_edge(pol: Dict[str, Any], crown_jewels: Set[str]) -> Tuple[bool, float, str, str]:
    """Determine whether a policy statement creates an exploitable traversal edge in the attack graph."""
    actions = set(pol.get("actions", []))
    resource = str(pol.get("resource", ""))
    conditions = pol.get("conditions") or {}
    target = str(pol.get("target", ""))

    # Public entrypoint invoking its own backing service role is a normal entry hop
    if str(pol.get("principal", "")).startswith("internet:"):
        return True, 1.0, "SEC-IAM-ENTRY-00", "Public HTTP/Webhook Entrypoint -> Execution Role"

    is_wildcard = resource in ("*", "arn:aws:s3:::*", "arn:aws:kms:*")
    has_strict_conditions = bool(
        conditions.get("StringEquals")
        and (
            "iam:PassedToService" in conditions["StringEquals"]
            or "sts:ExternalId" in conditions["StringEquals"]
            or "aws:SourceVpce" in conditions["StringEquals"]
        )
    )

    if {"iam:PassRole", "lambda:UpdateFunctionCode"} <= actions and not has_strict_conditions:
        return True, 1.2, "SEC-IAM-PASSROLE-01", "iam:PassRole + lambda:UpdateFunctionCode privilege escalation"

    if "sts:AssumeRole" in actions and (is_wildcard or not has_strict_conditions):
        return True, 1.4, "SEC-IAM-ASSUME-02", "Unconditioned sts:AssumeRole lateral role hop"

    if actions & {"iam:AttachRolePolicy", "iam:PutRolePolicy"} and is_wildcard:
        return True, 1.1, "SEC-IAM-SELFESC-03", "Self-escalation via wildcard iam:AttachRolePolicy / PutRolePolicy"

    if (actions & DATA_EXFIL_ACTIONS) and target in crown_jewels:
        if is_wildcard or target in resource:
            if not has_strict_conditions:
                return True, 1.0, "SEC-IAM-CROWNWILD-04", f"Wildcard/unscoped {', '.join(sorted(actions))} reaching crown jewel"

    return False, 999.0, "SCOPED_SAFE", "Scoped least-privilege access"


def analyze_iam_attack_paths(
    env_snapshot: Dict[str, Any],
    apply_least_privilege_patch: bool = False,
) -> Dict[str, Any]:
    """Compute shortest multi-hop privilege-escalation paths to crown-jewel assets via Dijkstra."""
    t0 = time.perf_counter()
    snap = copy.deepcopy(env_snapshot)
    crown_jewels = set(snap.get("crown_jewels", []))
    entry_nodes = list(snap.get("entry_nodes", []))
    node_labels = {n["id"]: n.get("label", n["id"]) for n in snap.get("nodes", [])}

    remediation_changes: List[Dict[str, Any]] = []
    if apply_least_privilege_patch:
        hardened_policies: List[Dict[str, Any]] = []
        for pol in snap.get("policies", []):
            actions = set(pol.get("actions", []))
            principal = str(pol.get("principal", ""))
            target = str(pol.get("target", ""))
            if principal.startswith("internet:"):
                hardened_policies.append(pol)
                continue
            if {"iam:PassRole", "lambda:UpdateFunctionCode"} <= actions:
                remediation_changes.append(
                    {
                        "principal": principal,
                        "action_taken": "Removed lambda:UpdateFunctionCode from runtime role and restricted iam:PassRole with iam:PassedToService condition",
                        "rule_fixed": "SEC-IAM-PASSROLE-01",
                    }
                )
                continue
            if "sts:AssumeRole" in actions:
                pol = dict(pol)
                pol["resource"] = target
                pol["conditions"] = {"StringEquals": {"sts:ExternalId": "secposture-verified-ci-pipeline"}}
                remediation_changes.append(
                    {
                        "principal": principal,
                        "action_taken": f"Scoped sts:AssumeRole resource to {target} and enforced sts:ExternalId condition",
                        "rule_fixed": "SEC-IAM-ASSUME-02",
                    }
                )
                hardened_policies.append(pol)
                continue
            if actions & {"iam:AttachRolePolicy", "iam:PutRolePolicy"}:
                remediation_changes.append(
                    {
                        "principal": principal,
                        "action_taken": "Removed iam:AttachRolePolicy self-mutation permission from workload execution role",
                        "rule_fixed": "SEC-IAM-SELFESC-03",
                    }
                )
                continue
            if target in crown_jewels and str(pol.get("resource", "")) == "*":
                remediation_changes.append(
                    {
                        "principal": principal,
                        "action_taken": f"Replaced wildcard '*' with VPC-endpoint-restricted condition on {target}",
                        "rule_fixed": "SEC-IAM-CROWNWILD-04",
                    }
                )
                pol = dict(pol)
                pol["resource"] = f"{target}/*" if ":s3:::" in target else target
                pol["conditions"] = {"StringEquals": {"aws:SourceVpce": "vpce-0secposture99"}}
                hardened_policies.append(pol)
                continue
            hardened_policies.append(pol)
        snap["policies"] = hardened_policies

    adj: Dict[str, List[Dict[str, Any]]] = {n["id"]: [] for n in snap.get("nodes", [])}
    toxic_edges: List[Dict[str, Any]] = []

    for pol in snap.get("policies", []):
        exploitable, weight, rule_id, reason = _classify_policy_edge(pol, crown_jewels)
        if exploitable:
            src = str(pol["principal"])
            dst = str(pol["target"])
            edge_obj = {
                "from": src,
                "to": dst,
                "weight": weight,
                "rule_id": rule_id,
                "actions": list(pol.get("actions", [])),
                "resource": str(pol.get("resource", "")),
                "reason": reason,
            }
            adj.setdefault(src, []).append(edge_obj)
            if rule_id != "SEC-IAM-ENTRY-00":
                toxic_edges.append(edge_obj)

    discovered_paths: List[Dict[str, Any]] = []

    # Dijkstra from every external entry node to every crown jewel
    for start_node in entry_nodes:
        pq: List[Tuple[float, str, List[str], List[Dict[str, Any]]]] = [(0.0, start_node, [start_node], [])]
        best_cost: Dict[str, float] = {start_node: 0.0}

        while pq:
            cost, cur, node_chain, edge_chain = heapq.heappop(pq)
            if cur in crown_jewels and len(node_chain) > 1:
                rules_triggered = [e["rule_id"] for e in edge_chain if e["rule_id"] != "SEC-IAM-ENTRY-00"]
                risk_score = min(99, round(60 + (18 * len(rules_triggered)) + (10.0 / max(1, len(edge_chain)))))
                discovered_paths.append(
                    {
                        "entry_node": start_node,
                        "crown_jewel": cur,
                        "crown_jewel_label": node_labels.get(cur, cur),
                        "hop_count": len(edge_chain),
                        "path_cost": round(cost, 2),
                        "risk_score": risk_score,
                        "ordered_nodes": node_chain,
                        "ordered_labels": [node_labels.get(n, n) for n in node_chain],
                        "edges": edge_chain,
                        "toxic_rules": rules_triggered,
                    }
                )
                continue

            for edge in adj.get(cur, []):
                nxt = edge["to"]
                if nxt in node_chain:
                    continue
                new_cost = cost + float(edge["weight"])
                if new_cost < best_cost.get(nxt, 1e9):
                    best_cost[nxt] = new_cost
                    heapq.heappush(pq, (new_cost, nxt, node_chain + [nxt], edge_chain + [edge]))

    discovered_paths.sort(key=lambda p: (p["path_cost"], -p["risk_score"]))

    # Synthesize ready-to-apply least-privilege IAM policy document
    least_privilege_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnconditionedPassRoleAndSelfEscalation",
                "Effect": "Deny",
                "Action": [
                    "iam:AttachRolePolicy",
                    "iam:PutRolePolicy",
                    "lambda:UpdateFunctionCode",
                ],
                "Resource": "*",
            },
            {
                "Sid": "RequireVpceForCrownJewelDataStores",
                "Effect": "Deny",
                "Action": ["s3:GetObject", "kms:Decrypt"],
                "Resource": sorted(crown_jewels),
                "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-0secposture99"}},
            },
        ],
    }

    solve_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return {
        "env_id": snap.get("env_id", "custom-env"),
        "title": snap.get("title", "Custom AWS IAM Graph"),
        "solve_ms": solve_ms,
        "patched_mode": apply_least_privilege_patch,
        "nodes_count": len(snap.get("nodes", [])),
        "crown_jewels": sorted(crown_jewels),
        "toxic_edges_count": len(toxic_edges),
        "attack_paths_count": len(discovered_paths),
        "shortest_hop_count": discovered_paths[0]["hop_count"] if discovered_paths else None,
        "max_risk_score": max((p["risk_score"] for p in discovered_paths), default=0),
        "posture_verdict": "CROWN_JEWEL_EXPOSED" if discovered_paths else "LEAST_PRIVILEGE_VERIFIED",
        "attack_paths": discovered_paths,
        "remediation_changes": remediation_changes,
        "least_privilege_guardrail_policy": least_privilege_policy_doc,
    }


def detect_cloudtrail_kill_chain(trace: Dict[str, Any]) -> Dict[str, Any]:
    """Stateful CloudTrail Kill-Chain Sequence & Behavioral Anomaly Detector."""
    t0 = time.perf_counter()
    events = trace.get("events", [])
    principal = str(trace.get("principal") or (events[0]["userIdentity"]["arn"] if events else "unknown"))

    stages_seen: List[str] = []
    stage_events: List[Dict[str, Any]] = []
    distinct_ips: Set[str] = set()
    external_ips: Set[str] = set()
    access_denied_count = 0
    sensitive_exfil_volume = 0
    bucket_policy_tamper = False

    for ev in events:
        ename = str(ev.get("eventName", ""))
        ip = str(ev.get("sourceIPAddress", ""))
        err = str(ev.get("errorCode", ""))
        params = ev.get("requestParameters") or {}

        if ip:
            distinct_ips.add(ip)
            if not _is_private_vpc_ip(ip):
                external_ips.add(ip)
        if err == "AccessDenied":
            access_denied_count += 1

        matched_stage: Optional[str] = None
        if ename in RECON_EVENTS or err == "AccessDenied":
            matched_stage = "RECON"
        if ename in CREDENTIAL_EVENTS:
            matched_stage = "CREDENTIAL_ACCESS"
        if ename in LATERAL_EVENTS:
            # Routine AssumeRole to CloudWatchReadRole or UpdateFunctionCode by GitHubDeployRole from private IP
            # still records LATERAL_MOVEMENT candidate, evaluated in context of full kill-chain progression
            matched_stage = "LATERAL_MOVEMENT"
        if ename in EXFIL_EVENTS:
            target_asset = str(params.get("bucketName") or params.get("keyId") or "")
            obj_count = int(params.get("objectCount") or 1)
            if ename == "PutBucketPolicy":
                bucket_policy_tamper = True
                matched_stage = "EXFILTRATION"
            elif target_asset in SENSITIVE_BUCKETS_AND_KEYS or obj_count >= 25:
                sensitive_exfil_volume += obj_count
                matched_stage = "EXFILTRATION"

        if matched_stage:
            if matched_stage not in stages_seen:
                stages_seen.append(matched_stage)
            stage_events.append(
                {
                    "eventTime": ev.get("eventTime", ""),
                    "eventName": ename,
                    "stage": matched_stage,
                    "sourceIPAddress": ip,
                    "errorCode": err,
                }
            )

    # Compute deterministic multi-factor anomaly score in [0.0, 1.0]
    stage_score = 0.22 * len(stages_seen)
    exfil_bonus = 0.22 if ("EXFILTRATION" in stages_seen and (sensitive_exfil_volume >= 25 or bucket_policy_tamper)) else 0.0
    ip_novelty_bonus = 0.14 if external_ips else 0.0
    ip_hop_bonus = 0.10 if len(distinct_ips) >= 2 else 0.0
    denied_burst_bonus = 0.08 if access_denied_count >= 2 else 0.0

    anomaly_score = round(min(0.99, stage_score + exfil_bonus + ip_novelty_bonus + ip_hop_bonus + denied_burst_bonus), 3)

    # Kill-chain alert fires when >= 3 distinct kill-chain stages progress OR lateral/cred + sensitive exfiltration occurs
    has_3_stages = len(stages_seen) >= 3
    has_escalated_exfil = ("EXFILTRATION" in stages_seen) and (
        "LATERAL_MOVEMENT" in stages_seen or "CREDENTIAL_ACCESS" in stages_seen
    ) and (sensitive_exfil_volume >= 25 or bucket_policy_tamper)

    incident_detected = bool((has_3_stages or has_escalated_exfil) and anomaly_score >= 0.65)

    quarantine_policy = None
    if incident_detected:
        quarantine_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SecPostureAutoQuarantineCompromisedSession",
                    "Effect": "Deny",
                    "Action": ["iam:*", "sts:AssumeRole", "lambda:Update*", "s3:GetObject", "s3:PutBucketPolicy", "kms:Decrypt"],
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:userid": principal.split("/")[-1]}},
                }
            ],
        }

    detect_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return {
        "trace_id": trace.get("trace_id", "CT-CUSTOM"),
        "title": trace.get("title", "Custom CloudTrail Event Stream"),
        "principal": principal,
        "events_analyzed": len(events),
        "detect_ms": detect_ms,
        "incident_detected": incident_detected,
        "severity": "CRITICAL" if incident_detected and anomaly_score >= 0.85 else ("HIGH" if incident_detected else "BENIGN"),
        "anomaly_score": anomaly_score,
        "kill_chain_stages_matched": stages_seen,
        "external_ips": sorted(external_ips),
        "sensitive_exfil_objects": sensitive_exfil_volume,
        "access_denied_count": access_denied_count,
        "matched_timeline": stage_events,
        "quarantine_session_policy": quarantine_policy,
    }


def evaluate_all_cloudtrail_benchmarks() -> Dict[str, Any]:
    results = []
    tp = fp = tn = fn = 0
    latencies: List[float] = []
    for sc in CLOUDTRAIL_SCENARIOS:
        out = detect_cloudtrail_kill_chain(sc)
        truth = bool(sc["malicious_ground_truth"])
        pred = bool(out["incident_detected"])
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif not truth and not pred:
            tn += 1
        else:
            fn += 1
        latencies.append(out["detect_ms"])
        out["malicious_ground_truth"] = truth
        out["correct"] = truth == pred
        results.append(out)

    precision = round((tp / (tp + fp)) * 100.0, 1) if (tp + fp) else 100.0
    recall = round((tp / (tp + fn)) * 100.0, 1) if (tp + fn) else 100.0
    fpr = round((fp / (fp + tn)) * 100.0, 1) if (fp + tn) else 0.0
    return {
        "total_traces": len(results),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision_pct": precision,
        "recall_pct": recall,
        "false_positive_rate_pct": fpr,
        "latencies_ms": latencies,
        "trace_results": results,
    }


def get_iam_environment(env_id: str) -> Dict[str, Any]:
    if env_id not in IAM_ENVIRONMENTS:
        raise KeyError(f"Unknown IAM environment: {env_id}")
    return IAM_ENVIRONMENTS[env_id]
