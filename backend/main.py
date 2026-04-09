import json
from pathlib import Path
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


def load_raw_events():
    if not DATA_FILE.exists():
        return []

    text = DATA_FILE.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # First try normal JSON parsing
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # Fallback for newline-delimited JSON
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def extract_alerts():
    raw_events = load_raw_events()
    alerts = []

    for i, event in enumerate(raw_events, start=1):
        event_type = event.get("event_type")

        if event_type != "alert":
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

    return alerts


def build_timeline():
    alerts = extract_alerts()
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


def build_incident_story():
    alerts = extract_alerts()
    timeline = build_timeline()

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
                "description": f'At {item["timestamp"]}, traffic from {item["src_ip"] or "unknown source"} to {item["dest_ip"] or "unknown destination"} generated the alert "{item["event"]}".',
                "severity": item["severity"],
            }
        )

    summary = (
        f"The observed incident begins with alert activity at {first_alert.get('timestamp') or 'an unknown time'} "
        f"and continues through {last_alert.get('timestamp') or 'an unknown time'}. "
        f"There are {len(alerts)} total alert events involving {len(unique_sources)} source system(s) "
        f"and {len(unique_dests)} destination system(s). The highest observed severity is {highest_severity}."
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


@app.get("/")
def root():
    return {"message": "SOC Copilot backend running"}


@app.get("/alerts")
def get_alerts():
    return extract_alerts()


@app.get("/summary")
def get_summary():
    alerts = extract_alerts()

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
    return build_timeline()


@app.get("/incident-story")
def get_incident_story():
    return build_incident_story()