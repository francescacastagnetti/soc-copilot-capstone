# backend/ai/feature_extractor.py

from collections import Counter
from typing import Any


def safe_lower(value: Any) -> str:
    return str(value or "").lower()


def safe_upper(value: Any) -> str:
    return str(value or "").upper()


def get_alert_by_id(alerts, event_id: str):
    for alert in alerts:
        if alert.get("event_id") == event_id:
            return alert
    return None


def get_most_common(values):
    filtered = [v for v in values if v]
    if not filtered:
        return "Unknown"
    counts = Counter(filtered)
    return counts.most_common(1)[0][0]


def build_related_alerts(alerts, event_id: str):
    selected = get_alert_by_id(alerts, event_id)
    if not selected:
        return []

    related = []

    for alert in alerts:
        if alert.get("event_id") == event_id:
            continue

        same_source = selected.get("src_ip") and alert.get("src_ip") == selected.get("src_ip")
        same_dest = selected.get("dest_ip") and alert.get("dest_ip") == selected.get("dest_ip")
        same_host = (
            selected.get("hostname")
            and alert.get("hostname")
            and alert.get("hostname") == selected.get("hostname")
        )

        if same_source or same_dest or same_host:
            related.append(alert)

    related.sort(key=lambda x: x.get("timestamp") or "")
    return related


def compute_behavior_profile(alerts):
    """
    Build simple dataset-wide baselines to support anomaly-aware scoring.
    """
    src_counter = Counter()
    dest_counter = Counter()
    host_counter = Counter()
    method_counter = Counter()
    proto_counter = Counter()
    signature_token_counter = Counter()

    for alert in alerts:
        src = alert.get("src_ip")
        dst = alert.get("dest_ip")
        host = alert.get("hostname")
        method = safe_upper(alert.get("http_method"))
        proto = safe_upper(alert.get("proto"))
        signature = safe_lower(alert.get("signature"))

        if src:
            src_counter[src] += 1
        if dst:
            dest_counter[dst] += 1
        if host:
            host_counter[host] += 1
        if method:
            method_counter[method] += 1
        if proto:
            proto_counter[proto] += 1

        for token in signature.replace("/", " ").replace("-", " ").split():
            if len(token) >= 4:
                signature_token_counter[token] += 1

    return {
        "src_counter": src_counter,
        "dest_counter": dest_counter,
        "host_counter": host_counter,
        "method_counter": method_counter,
        "proto_counter": proto_counter,
        "signature_token_counter": signature_token_counter,
        "total_alerts": len(alerts),
    }


def extract_alert_features(alert, alerts=None, profile=None):
    """
    Extract features for one alert.
    This version is more sophisticated than simple keyword checks because it
    includes repeated-entity correlation and lightweight anomaly signals.
    """
    alerts = alerts or []
    profile = profile or compute_behavior_profile(alerts)

    signature = safe_lower(alert.get("signature"))
    method = safe_upper(alert.get("http_method"))
    proto = safe_upper(alert.get("proto"))
    url = safe_lower(alert.get("url"))
    hostname = safe_lower(alert.get("hostname"))

    severity = int(alert.get("severity") or 0)
    src_ip = alert.get("src_ip")
    dest_ip = alert.get("dest_ip")

    src_count = profile["src_counter"].get(src_ip, 0) if src_ip else 0
    dest_count = profile["dest_counter"].get(dest_ip, 0) if dest_ip else 0
    host_count = profile["host_counter"].get(alert.get("hostname"), 0) if alert.get("hostname") else 0
    method_count = profile["method_counter"].get(method, 0) if method else 0
    proto_count = profile["proto_counter"].get(proto, 0) if proto else 0

    unusual_method = bool(method) and method_count <= 1 and profile["total_alerts"] >= 3
    unusual_proto = bool(proto) and proto_count <= 1 and profile["total_alerts"] >= 3
    unusual_host = bool(hostname) and host_count <= 1 and profile["total_alerts"] >= 3

    login_terms = ["login", "credential", "auth", "password", "signin", "session"]
    exfil_terms = ["exfil", "collect", "download", "outbound", "transfer", "leak"]
    recon_terms = ["scan", "probe", "recon", "enumeration", "discovery", "fingerprint"]
    dns_terms = ["dns", "domain", "resolver"]
    web_terms = ["http", "web", "uri", "request"]

    has_login_terms = any(token in signature or token in url for token in login_terms)
    has_exfil_terms = any(token in signature or token in url for token in exfil_terms)
    has_recon_terms = any(token in signature or token in url for token in recon_terms)
    has_dns_terms = any(token in signature or token in url for token in dns_terms)
    has_web_terms = any(token in signature for token in web_terms) or bool(url) or bool(hostname)

    suspicious_methods = {"POST", "PUT", "DELETE"}
    suspicious_method = method in suspicious_methods

    repeated_source = src_count >= 2
    repeated_dest = dest_count >= 2
    concentrated_source = src_count >= 3
    concentrated_dest = dest_count >= 3

    attack_phase = "general"
    if has_recon_terms:
        attack_phase = "reconnaissance"
    elif has_login_terms:
        attack_phase = "credential-access"
    elif has_exfil_terms:
        attack_phase = "exfiltration"
    elif has_dns_terms:
        attack_phase = "dns-activity"
    elif has_web_terms:
        attack_phase = "web-activity"

    anomaly_signals = []
    if unusual_method:
        anomaly_signals.append("rare HTTP method")
    if unusual_proto:
        anomaly_signals.append("rare protocol")
    if unusual_host:
        anomaly_signals.append("rare hostname")
    if concentrated_source:
        anomaly_signals.append("repeated source concentration")
    if concentrated_dest:
        anomaly_signals.append("repeated destination concentration")

    return {
        "severity": severity,
        "signature": signature,
        "method": method,
        "proto": proto,
        "url": url,
        "hostname": hostname,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "url_present": bool(url),
        "host_present": bool(hostname),
        "is_post": method == "POST",
        "suspicious_method": suspicious_method,
        "has_login_terms": has_login_terms,
        "has_exfil_terms": has_exfil_terms,
        "has_recon_terms": has_recon_terms,
        "has_dns_terms": has_dns_terms,
        "has_web_terms": has_web_terms,
        "same_source_count": src_count,
        "same_dest_count": dest_count,
        "same_host_count": host_count,
        "method_count": method_count,
        "proto_count": proto_count,
        "repeated_source": repeated_source,
        "repeated_dest": repeated_dest,
        "concentrated_source": concentrated_source,
        "concentrated_dest": concentrated_dest,
        "unusual_method": unusual_method,
        "unusual_proto": unusual_proto,
        "unusual_host": unusual_host,
        "anomaly_signals": anomaly_signals,
        "attack_phase": attack_phase,
    }