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


# ---------------------------
# 🧠 Helper: build key findings
# ---------------------------
def build_key_findings(features):
    findings = []

    if features["has_login_terms"]:
        findings.append("Credential-related activity detected")

    if features["has_exfil_terms"]:
        findings.append("Potential data movement behavior observed")

    if features["has_recon_terms"]:
        findings.append("Reconnaissance-like behavior detected")

    if features["repeated_source"]:
        findings.append("Repeated activity from the same source IP")

    if features["suspicious_method"]:
        findings.append(f"Suspicious HTTP method used ({features['method']})")

    if features["unusual_method"] or features["unusual_proto"]:
        findings.append("Unusual behavior compared to dataset baseline")

    return findings


# ---------------------------
# 🧠 Helper: impact assessment
# ---------------------------
def build_impact_assessment(features):
    phase = features.get("attack_phase", "general")

    if phase == "credential-access":
        return "This activity may indicate attempted credential use or compromise risk."

    if phase == "exfiltration":
        return "This behavior may indicate potential data exfiltration or unauthorized data transfer."

    if phase == "reconnaissance":
        return "This activity may represent early-stage reconnaissance preceding further attacks."

    return "This activity may represent suspicious or anomalous network behavior requiring review."


# ---------------------------
# 🧠 Helper: narrative explanation
# ---------------------------
def build_narrative(alert, features, score, reasons):
    src = alert.get("src_ip") or "an unknown source"
    dst = alert.get("dest_ip") or "an unknown destination"
    sig = alert.get("signature") or "an alert"
    phase = features.get("attack_phase", "general")

    explanation = (
        f"TRACE analysis indicates that traffic from {src} to {dst} triggered the alert \"{sig}\". "
    )

    explanation += f"This activity most closely aligns with {phase.replace('-', ' ')} behavior. "

    if reasons:
        explanation += "Key contributing factors include "
        explanation += ", ".join(reasons[:3]) + ". "

    # Correlation language
    if features["repeated_source"]:
        explanation += "Repeated activity from the same source suggests this is not an isolated event. "

    if features["concentrated_source"]:
        explanation += "The concentration of activity from a single source increases the likelihood of coordinated behavior. "

    explanation += (
        f"Overall, TRACE assigned a score of {score}, reflecting an elevated risk associated with {phase.replace('-', ' ')} activity."
    )

    return explanation


# ---------------------------
# 🧠 Multi-alert correlation insight
# ---------------------------
def build_incident_summary(alerts, ranked):
    if len(alerts) < 2:
        return "The observed activity appears limited to a single alert event."

    phases = [item["features"]["attack_phase"] for item in ranked]
    unique_phases = list(set(phases))

    if "credential-access" in unique_phases and "exfiltration" in unique_phases:
        return "Observed alerts suggest a progression from credential access activity to potential outbound behavior."

    if "reconnaissance" in unique_phases:
        return "Observed alerts include reconnaissance-like activity, which may precede further attack stages."

    return "Multiple alerts indicate repeated or sustained suspicious activity across the environment."


# ---------------------------
# 🧠 Rank alerts
# ---------------------------
def rank_alerts(alerts):
    profile = compute_behavior_profile(alerts)
    ranked = []

    for alert in alerts:
        features = extract_alert_features(alert, alerts, profile)
        score, reasons = score_alert(features)

        ranked.append({
            "alert": alert,
            "features": features,
            "score": score,
            "reasons": reasons,
        })

    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked


# ---------------------------
# 🔥 TRACE OVERVIEW
# ---------------------------
def build_trace_overview(alerts):
    if not alerts:
        return {
            "trace_status": "No alerts available",
            "priority": "No active priority",
            "priority_message": "TRACE is waiting for alert telemetry.",
            "recommended_action": "Ensure data ingestion is active.",
            "active_incident_count": 0,
            "confidence": "N/A",
        }

    ranked = rank_alerts(alerts)
    top = ranked[0]

    alert = top["alert"]
    features = top["features"]
    score = top["score"]
    reasons = top["reasons"]

    return {
        "trace_status": "Active monitoring",
        "priority": classify_priority_from_score(score, features),
        "priority_message": build_narrative(alert, features, score, reasons),
        "recommended_action": build_impact_assessment(features),
        "incident_summary": build_incident_summary(alerts, ranked),
        "key_findings": build_key_findings(features),
        "confidence": classify_confidence_from_score(score),
        "confidence_breakdown": build_confidence_breakdown(score, reasons),
    }


# ---------------------------
# 🔥 TRACE EXPLAIN
# ---------------------------
def build_trace_explanation(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    ranked = rank_alerts(alerts)
    profile = compute_behavior_profile(alerts)

    features = extract_alert_features(alert, alerts, profile)
    score, reasons = score_alert(features)

    return {
        "event_id": event_id,
        "explanation": build_narrative(alert, features, score, reasons),
        "impact_assessment": build_impact_assessment(features),
        "key_findings": build_key_findings(features),
        "confidence": classify_confidence_from_score(score),
        "confidence_breakdown": build_confidence_breakdown(score, reasons),
        "score": score,
    }


# ---------------------------
# 🔥 NEXT STEPS
# ---------------------------
def build_trace_next_steps(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    profile = compute_behavior_profile(alerts)
    features = extract_alert_features(alert, alerts, profile)
    score, reasons = score_alert(features)

    steps = [
        "Review surrounding timeline events for context.",
        "Check for repeated activity from the same source IP.",
        "Validate whether this behavior matches expected system activity.",
    ]

    if features["has_login_terms"]:
        steps.append("Inspect authentication-related endpoints and credential flows.")

    if features["has_exfil_terms"]:
        steps.append("Investigate outbound traffic patterns and potential data transfers.")

    if features["has_recon_terms"]:
        steps.append("Determine whether reconnaissance activity escalated to access attempts.")

    return {
        "event_id": event_id,
        "next_steps": steps,
        "score_drivers": reasons[:5],
    }


# ---------------------------
# 🔗 RELATED
# ---------------------------
def build_trace_related(alerts, event_id: str):
    return build_related_alerts(alerts, event_id)