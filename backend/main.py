import json
from pathlib import Path
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR.parent / "sample_data" / "eve.json"

_CACHE = {
    "mtime": None,
    "raw_events": [],
    "alerts": [],
}


def load_raw_events():
    if not DATA_FILE.exists():
        _CACHE["mtime"] = None
        _CACHE["raw_events"] = []
        _CACHE["alerts"] = []
        return []

    current_mtime = DATA_FILE.stat().st_mtime

    if _CACHE["mtime"] == current_mtime and _CACHE["raw_events"]:
        return _CACHE["raw_events"]

    text = DATA_FILE.read_text(encoding="utf-8").strip()
    if not text:
        _CACHE["mtime"] = current_mtime
        _CACHE["raw_events"] = []
        _CACHE["alerts"] = []
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict):
            events = [parsed]
        else:
            events = []
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    _CACHE["mtime"] = current_mtime
    _CACHE["raw_events"] = events
    _CACHE["alerts"] = []
    return events


def extract_alerts():
    raw_events = load_raw_events()

    current_mtime = _CACHE["mtime"]
    if _CACHE["alerts"] and current_mtime is not None:
      return _CACHE["alerts"]

    alerts = []

    for i, event in enumerate(raw_events, start=1):
        if event.get("event_type") != "alert":
            continue

        alerts.append(
            {
                "event_id": f"evt-{i:03}",
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
                "severity": event.get("alert", {}).get("severity"),
                "signature": event.get("alert", {}).get("signature"),
                "hostname": event.get("http", {}).get("hostname"),
                "url": event.get("http", {}).get("url"),
                "http_method": event.get("http", {}).get("http_method"),
                "raw": event,
            }
        )

    _CACHE["alerts"] = alerts
    return alerts


def get_alerts_data():
    return extract_alerts()


def build_timeline(alerts):
    sorted_alerts = sorted(alerts, key=lambda x: x["timestamp"] or "")
    return [
        {
            "timestamp": a["timestamp"],
            "event": a["signature"],
            "src_ip": a["src_ip"],
            "dest_ip": a["dest_ip"],
            "severity": a["severity"],
            "event_id": a["event_id"],
        }
        for a in sorted_alerts
    ]


def get_alert_by_id(alerts, event_id: str):
    for alert in alerts:
        if alert["event_id"] == event_id:
            return alert
    return None


def build_incident_story(alerts):
    timeline = build_timeline(alerts)

    if not alerts:
        return {
            "title": "No active alert story available",
            "summary": "No alert events were found in the current dataset.",
            "steps": [],
            "analyst_notes": [
                "Verify that telemetry is being ingested correctly.",
                "Confirm that the log file contains alert events rather than only stats or metadata.",
            ],
        }

    sorted_alerts = sorted(alerts, key=lambda x: x["timestamp"] or "")
    first_alert = sorted_alerts[0]
    last_alert = sorted_alerts[-1]

    unique_sources = sorted({a["src_ip"] for a in alerts if a.get("src_ip")})
    unique_dests = sorted({a["dest_ip"] for a in alerts if a.get("dest_ip")})
    highest_severity = max([(a.get("severity") or 0) for a in alerts], default=0)

    steps = []
    for idx, item in enumerate(timeline[:6], start=1):
        steps.append(
            {
                "step_number": idx,
                "timestamp": item["timestamp"],
                "event": item["event"],
                "event_id": item["event_id"],
                "description": (
                    f'At {item["timestamp"]}, traffic from '
                    f'{item["src_ip"] or "unknown source"} to '
                    f'{item["dest_ip"] or "unknown destination"} generated '
                    f'the alert "{item["event"]}".'
                ),
                "severity": item["severity"],
            }
        )

    summary = (
        f'The observed incident begins with alert activity at '
        f'{first_alert.get("timestamp") or "an unknown time"} and continues through '
        f'{last_alert.get("timestamp") or "an unknown time"}. '
        f"There are {len(alerts)} total alert events involving "
        f"{len(unique_sources)} source system(s) and {len(unique_dests)} "
        f"destination system(s). The highest observed severity is {highest_severity}."
    )

    analyst_notes = [
        "Review whether the same source IP appears repeatedly across the alert chain.",
        "Check whether multiple alerts target the same destination or URL path.",
        "Use the timeline to identify whether the alerts suggest reconnaissance, access, or follow-on activity.",
        "Compare the raw event fields to verify whether this is a true positive or noisy traffic.",
    ]

    return {
        "title": "Incident Story",
        "summary": summary,
        "steps": steps,
        "analyst_notes": analyst_notes,
    }


def build_related_alerts(alerts, event_id: str):
    selected = get_alert_by_id(alerts, event_id)
    if not selected:
        return []

    related = []

    for alert in alerts:
        if alert["event_id"] == event_id:
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

    related = sorted(related, key=lambda x: x["timestamp"] or "")
    return related


def classify_priority(alert):
    severity = alert.get("severity") or 0
    signature = (alert.get("signature") or "").lower()
    method = (alert.get("http_method") or "").upper()

    if severity >= 4:
        return "Critical Incident"
    if "credential" in signature or "login" in signature or method == "POST":
        return "Credential Activity"
    if "outbound" in signature or "exfil" in signature or "collect" in signature:
        return "Potential Exfiltration"
    if severity == 3:
        return "High-Priority Alert"
    if "scan" in signature or "probe" in signature:
        return "Reconnaissance Activity"
    return "Suspicious Network Activity"


def classify_risk_category(alert):
    signature = (alert.get("signature") or "").lower()
    method = (alert.get("http_method") or "").upper()
    url = (alert.get("url") or "").lower()

    if "credential" in signature or "login" in signature or method == "POST":
        return "Credential Access Risk"
    if "outbound" in signature or "collect" in signature or "exfil" in signature:
        return "Data Movement Risk"
    if "scan" in signature or "probe" in signature:
        return "Reconnaissance Risk"
    if "dns" in signature:
        return "DNS Activity Risk"
    if "http" in signature or url:
        return "Web Traffic Risk"
    return "General Network Risk"


def classify_confidence(alert):
    severity = alert.get("severity") or 0
    signature = (alert.get("signature") or "").lower()
    method = (alert.get("http_method") or "").upper()
    url = (alert.get("url") or "").lower()

    score = 0

    if severity >= 4:
        score += 3
    elif severity == 3:
        score += 2
    elif severity == 2:
        score += 1

    if method == "POST":
        score += 1

    for token in ["credential", "login", "exfil", "outbound", "scan", "probe", "collect"]:
        if token in signature:
            score += 1

    if url:
        score += 1

    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Moderate"


def build_priority_message(alert):
    src = alert.get("src_ip") or "unknown source"
    dst = alert.get("dest_ip") or "unknown destination"
    host = alert.get("hostname") or "unknown host"
    severity = alert.get("severity") or 0
    signature = alert.get("signature") or "unknown alert"

    if severity >= 4:
        return f"TRACE flagged traffic from {src} to {dst} as the current top-priority issue because the event severity is critical."
    if "credential" in signature.lower() or "login" in signature.lower():
        return f"TRACE identified behavior consistent with possible authentication-related activity involving {src}, {dst}, and host {host}."
    if "outbound" in signature.lower() or "collect" in signature.lower() or "exfil" in signature.lower():
        return f"TRACE observed activity that may indicate suspicious outbound communication between {src} and {dst}."
    return f'TRACE recommends reviewing surrounding events for {src} and {dst} to determine whether "{signature}" is isolated or part of a larger chain.'


def build_recommended_action(alert):
    severity = alert.get("severity") or 0
    signature = (alert.get("signature") or "").lower()
    method = (alert.get("http_method") or "").upper()

    if severity >= 4:
        return "Immediately validate the alert, inspect adjacent timeline activity, and prioritize containment if the behavior is confirmed."
    if "credential" in signature or "login" in signature or method == "POST":
        return "Review related requests, login paths, and repeated source activity for possible credential use or submission attempts."
    if "outbound" in signature or "exfil" in signature or "collect" in signature:
        return "Inspect destination patterns, transferred resources, and repeated outbound activity for signs of collection or exfiltration."
    if "scan" in signature or "probe" in signature:
        return "Review surrounding reconnaissance indicators and determine whether the source progressed beyond discovery behavior."
    return "Examine the raw event fields and nearby alerts to determine whether the event is benign, noisy, or part of a broader sequence."


def get_most_common(values):
    filtered = [v for v in values if v]
    if not filtered:
        return "Unknown"
    counts = Counter(filtered)
    return counts.most_common(1)[0][0]


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
        }

    top_alert = sorted(alerts, key=lambda a: (a.get("severity") or 0), reverse=True)[0]
    priority = classify_priority(top_alert)
    priority_message = build_priority_message(top_alert)
    risk_category = classify_risk_category(top_alert)
    recommended_action = build_recommended_action(top_alert)
    confidence = classify_confidence(top_alert)

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
    }


def build_trace_explanation(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    src = alert.get("src_ip") or "unknown source"
    dst = alert.get("dest_ip") or "unknown destination"
    sig = alert.get("signature") or "unknown alert"
    method = alert.get("http_method") or "unknown method"
    host = alert.get("hostname") or "unknown host"
    url = alert.get("url") or "/"
    sev = alert.get("severity") or 0
    confidence = classify_confidence(alert)

    explanation = (
        f'TRACE determined that traffic from {src} to {dst} triggered the alert "{sig}". '
        f"The observed request used {method} against {host}{url}. "
        f"This event has severity {sev} and should be reviewed in the context of surrounding related activity."
    )

    evidence = [
        f"Source IP: {src}",
        f"Destination IP: {dst}",
        f"Protocol: {alert.get('proto') or 'unknown'}",
        f"Method: {method}",
        f"Host: {host}",
        f"URL: {url}",
        f"Severity: {sev}",
    ]

    return {
        "event_id": event_id,
        "explanation": explanation,
        "evidence": evidence,
        "confidence": confidence,
    }


def build_trace_next_steps(alerts, event_id: str):
    alert = get_alert_by_id(alerts, event_id)
    if not alert:
        return {"error": "Alert not found"}

    steps = [
        "Review nearby timeline events to determine what happened immediately before and after this alert.",
        "Check for repeated activity from the same source IP.",
        "Compare whether the same destination IP or hostname appears in multiple alerts.",
        "Inspect the raw event fields to verify whether the alert reflects suspicious or expected traffic.",
    ]

    if alert.get("http_method"):
        steps.append(
            "Review the associated HTTP method and URL path for possible credential use, access attempts, or follow-on activity."
        )

    if alert.get("severity") and alert.get("severity") >= 3:
        steps.append(
            "Prioritize this event for analyst attention because it is high severity."
        )

    return {
        "event_id": event_id,
        "next_steps": steps,
    }


@app.get("/")
def root():
    return {"message": "SOC Copilot backend running"}


@app.get("/alerts")
def get_alerts():
    return get_alerts_data()


@app.get("/summary")
def get_summary():
    alerts = get_alerts_data()

    unique_sources = len(set(a["src_ip"] for a in alerts if a["src_ip"]))
    unique_dests = len(set(a["dest_ip"] for a in alerts if a["dest_ip"]))
    high_severity = len([a for a in alerts if (a["severity"] or 0) >= 3])

    return {
        "total_alerts": len(alerts),
        "high_severity": high_severity,
        "unique_sources": unique_sources,
        "unique_destinations": unique_dests,
    }


@app.get("/timeline")
def get_timeline():
    alerts = get_alerts_data()
    return build_timeline(alerts)


@app.get("/incident-story")
def get_incident_story():
    alerts = get_alerts_data()
    return build_incident_story(alerts)


@app.get("/trace/overview")
def get_trace_overview():
    alerts = get_alerts_data()
    return build_trace_overview(alerts)


@app.get("/trace/explain/{event_id}")
def get_trace_explain(event_id: str):
    alerts = get_alerts_data()
    return build_trace_explanation(alerts, event_id)


@app.get("/trace/next-steps/{event_id}")
def get_trace_next_steps(event_id: str):
    alerts = get_alerts_data()
    return build_trace_next_steps(alerts, event_id)


@app.get("/trace/related/{event_id}")
def get_trace_related(event_id: str):
    alerts = get_alerts_data()
    return build_related_alerts(alerts, event_id)