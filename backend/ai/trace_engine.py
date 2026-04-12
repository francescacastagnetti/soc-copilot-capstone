# backend/ai/trace_engine.py

from .feature_extractor import (
    build_related_alerts,
    compute_behavior_profile,
    extract_alert_features,
    get_alert_by_id,
    get_most_common,
)
from .scoring import (
    build_confidence_breakdown,
    classify_confidence_from_score,
    classify_priority_from_score,
    classify_risk_category,
    score_alert,
)


def build_priority_message(alert, features, score, reasons):
    src = alert.get("src_ip") or "unknown source"
    dst = alert.get("dest_ip") or "unknown destination"
    host = alert.get("hostname") or "unknown host"
    phase = features.get("attack_phase", "general")

    if reasons:
        lead = ", ".join(reasons[:3])
    else:
        lead = "suspicious network characteristics"

    return (
        f"TRACE elevated traffic from {src} to {dst} involving host {host} "
        f"because it aligns with {phase} behavior and scored {score} based on {lead}."
    )


def build_recommended_action(features):
    phase = features.get("attack_phase", "general")

    if phase == "credential-access":
        return (
            "Review authentication endpoints, repeated login-related requests, and surrounding "
            "source activity to determine whether the behavior reflects credential use or abuse."
        )

    if phase == "exfiltration":
        return (
            "Inspect outbound destinations, repeated transfers, and adjacent events to determine "
            "whether the activity reflects collection or data movement."
        )

    if phase == "reconnaissance":
        return (
            "Review the timeline for follow-on behavior after discovery activity and determine "
            "whether reconnaissance escalated into access attempts."
        )

    if phase == "dns-activity":
        return (
            "Validate the observed DNS behavior, inspect repetition against the same host or "
            "destination, and check whether the activity aligns with expected resolution patterns."
        )

    return (
        "Inspect the raw event, compare nearby alerts, and determine whether this event is isolated, "
        "benign, or part of a broader sequence."
    )


def rank_alerts(alerts):
    profile = compute_behavior_profile(alerts)
    ranked = []

    for alert in alerts:
        features = extract_alert_features(alert, alerts, profile)
        score, reasons = score_alert(features)
        ranked.append(
            {
                "alert": alert,
                "features": features,
                "score": score,
                "reasons": reasons,
            }
        )

    ranked.sort(
        key=lambda item: (item["score"], item["alert"].get("severity") or 0, item["alert"].get("timestamp") or ""),
        reverse=True,
    )
    return ranked


def build_trace_overview(alerts):
    if not alerts:
        return {
            "trace_status": "No alerts available",
            "priority": "No active priority",
            "priority_message": "TRACE is waiting for alert telemetry before assigning investigative priority.",
            "recommended_action": "Confirm that telemetry is being ingested and that alert events are present in the dataset.",
            "active_incident_count": 0,
            "top_risk": "No risk identified",
            "risk_category": "No category",
            "most_affected_source": "Unknown",
            "most_affected_destination": "Unknown",
            "confidence": "N/A",
            "confidence_breakdown": {
                "score": 0,
                "drivers": [],
                "confidence_basis": "No alert evidence available."
            },
        }

    ranked = rank_alerts(alerts)
    top = ranked[0]

    top_alert = top["alert"]
    top_features = top["features"]
    top_score = top["score"]
    top_reasons = top["reasons"]

    priority = classify_priority_from_score(top_score, top_features)
    risk_category = classify_risk_category(top_features)
    confidence = classify_confidence_from_score(top_score)
    priority_message = build_priority_message(top_alert, top_features, top_score, top_reasons)
    recommended_action = build_recommended_action(top_features)
    confidence_breakdown = build_confidence_breakdown(top_score, top_reasons)

    most_affected_source = get_most_common([a.get("src_ip") for a in alerts])
    most_affected_destination = get_most_common([a.get("dest_ip") for a in alerts])

    return {
        "trace_status": "Active monitoring",
        "priority": priority,
        "priority_message": priority_message,
        "recommended_action": recommended_action,
        "active_incident_count": len(alerts),
        "top_risk": top_alert.get("signature") or "Unknown risk",
        "risk_category": risk_category,
        "most_affected_source": most_affected_source,
        "most_affected_destination": most_affected_destination,
        "confidence": confidence,
        "confidence_breakdown": confidence_breakdown,
    }


def build_trace_explanation(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    profile = compute_behavior_profile(alerts)
    features = extract_alert_features(alert, alerts, profile)
    score, reasons = score_alert(features)
    confidence = classify_confidence_from_score(score)
    confidence_breakdown = build_confidence_breakdown(score, reasons)

    src = alert.get("src_ip") or "unknown source"
    dst = alert.get("dest_ip") or "unknown destination"
    sig = alert.get("signature") or "unknown alert"
    method = alert.get("http_method") or "unknown method"
    host = alert.get("hostname") or "unknown host"
    url = alert.get("url") or "/"
    sev = alert.get("severity") or 0
    proto = alert.get("proto") or "unknown"
    phase = features.get("attack_phase", "general")

    if reasons:
        reason_text = ", ".join(reasons[:4])
    else:
        reason_text = "limited suspicious indicators"

    explanation = (
        f'TRACE determined that traffic from {src} to {dst} triggered the alert "{sig}". '
        f"This event maps most closely to {phase} behavior, used method {method}, protocol {proto}, "
        f"host {host}, and URL path {url}. The event severity is {sev}. "
        f"TRACE assigned a score of {score} and confidence {confidence} based on {reason_text}."
    )

    evidence = [
        f"Source IP: {src}",
        f"Destination IP: {dst}",
        f"Protocol: {proto}",
        f"Method: {method}",
        f"Host: {host}",
        f"URL: {url}",
        f"Severity: {sev}",
        f"Attack phase: {phase}",
        f"Repeated source count: {features['same_source_count']}",
        f"Repeated destination count: {features['same_dest_count']}",
        f"Repeated host count: {features['same_host_count']}",
    ]

    return {
        "event_id": event_id,
        "explanation": explanation,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_breakdown": confidence_breakdown,
        "score": score,
    }


def build_trace_next_steps(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    profile = compute_behavior_profile(alerts)
    features = extract_alert_features(alert, alerts, profile)
    score, reasons = score_alert(features)

    steps = [
        "Review nearby timeline events to determine what happened immediately before and after this alert.",
        "Check whether the same source IP appears repeatedly across the incident chain.",
        "Compare whether the same destination IP or hostname appears in multiple alerts.",
        "Inspect the raw event fields to determine whether the event is benign, noisy, or part of a broader sequence.",
    ]

    if features["has_login_terms"]:
        steps.append(
            "Inspect authentication-related paths and determine whether the activity reflects suspicious login or credential use."
        )

    if features["has_exfil_terms"]:
        steps.append(
            "Review outbound communication and transferred resources for possible collection or exfiltration behavior."
        )

    if features["has_recon_terms"]:
        steps.append(
            "Determine whether the observed reconnaissance behavior was followed by access or submission activity."
        )

    if features["unusual_method"] or features["unusual_proto"] or features["unusual_host"]:
        steps.append(
            "Validate the anomaly signals by comparing this event against expected methods, protocols, and hostnames in the dataset."
        )

    if score >= 8:
        steps.append("Prioritize this event for analyst attention because its combined TRACE score is elevated.")

    return {
        "event_id": event_id,
        "next_steps": steps,
        "score_drivers": reasons[:5],
    }


def build_trace_related(alerts, event_id: str):
    return build_related_alerts(alerts, event_id)