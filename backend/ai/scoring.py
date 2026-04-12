# backend/ai/scoring.py

def score_alert(features):
    """
    Hybrid scoring:
    - severity
    - behavior indicators
    - repeated entity correlation
    - lightweight anomaly signals
    - phase-sensitive adjustment

    This version creates more separation between credential, recon,
    and exfiltration-style alerts.
    """
    score = 0
    reasons = []

    severity = features["severity"]
    attack_phase = features.get("attack_phase", "general")

    # Severity contribution
    if severity >= 4:
        score += 6
        reasons.append("critical severity")
    elif severity == 3:
        score += 4
        reasons.append("high severity")
    elif severity == 2:
        score += 2
        reasons.append("moderate severity")
    elif severity == 1:
        score += 1
        reasons.append("low severity")

    # Behavior contribution
    if features["suspicious_method"]:
        score += 2
        reasons.append(f"suspicious method {features['method']}")

    if features["has_login_terms"]:
        score += 3
        reasons.append("credential-related indicators")

    if features["has_exfil_terms"]:
        score += 4
        reasons.append("possible exfiltration indicators")

    if features["has_recon_terms"]:
        score += 2
        reasons.append("reconnaissance indicators")

    if features["has_dns_terms"]:
        score += 1
        reasons.append("DNS-related indicators")

    if features["has_web_terms"]:
        score += 1
        reasons.append("web activity indicators")

    # Correlation contribution
    if features["concentrated_source"]:
        score += 4
        reasons.append("same source appears repeatedly")
    elif features["repeated_source"]:
        score += 2
        reasons.append("source seen more than once")

    if features["concentrated_dest"]:
        score += 4
        reasons.append("same destination appears repeatedly")
    elif features["repeated_dest"]:
        score += 2
        reasons.append("destination seen more than once")

    if features["same_host_count"] >= 3:
        score += 2
        reasons.append("same host appears repeatedly")
    elif features["same_host_count"] == 2:
        score += 1
        reasons.append("host seen more than once")

    # Lightweight anomaly contribution
    if features["unusual_method"]:
        score += 2
        reasons.append("rare HTTP method in dataset")

    if features["unusual_proto"]:
        score += 2
        reasons.append("rare protocol in dataset")

    if features["unusual_host"]:
        score += 1
        reasons.append("rare hostname in dataset")

    # Phase-sensitive adjustment
    if attack_phase == "exfiltration":
        score += 2
        reasons.append("higher-risk attack phase")
    elif attack_phase == "credential-access":
        score += 1
        reasons.append("credential access phase")
    elif attack_phase == "reconnaissance":
        score += 0  # intentionally lower unless paired with repetition/severity

    return score, reasons


def classify_priority_from_score(score, features):
    if score >= 15:
        return "Critical Incident"
    if features["has_exfil_terms"] and score >= 11:
        return "Potential Exfiltration"
    if features["has_login_terms"] and score >= 9:
        return "Credential Activity"
    if features["has_recon_terms"] and score >= 7:
        return "Reconnaissance Activity"
    if score >= 9:
        return "High-Priority Alert"
    if score >= 6:
        return "Elevated Suspicious Activity"
    return "Suspicious Network Activity"


def classify_risk_category(features):
    if features["has_login_terms"]:
        return "Credential Access Risk"
    if features["has_exfil_terms"]:
        return "Data Movement Risk"
    if features["has_recon_terms"]:
        return "Reconnaissance Risk"
    if features["has_dns_terms"]:
        return "DNS Activity Risk"
    if features["has_web_terms"]:
        return "Web Traffic Risk"
    return "General Network Risk"


def classify_confidence_from_score(score):
    if score >= 15:
        return "High"
    if score >= 9:
        return "Medium"
    return "Moderate"


def build_confidence_breakdown(score, reasons):
    if not reasons:
        return {
            "score": score,
            "drivers": ["limited evidence"],
            "confidence_basis": "TRACE found only weak or isolated signals.",
        }

    top_reasons = reasons[:4]
    return {
        "score": score,
        "drivers": top_reasons,
        "confidence_basis": (
            "TRACE confidence is based on the combined effect of severity, "
            "behavior indicators, repeated-entity correlation, anomaly signals, "
            "and attack-phase weighting."
        ),
    }