import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ai.trace_engine import (
    build_trace_overview,
    build_trace_explanation,
    build_trace_next_steps,
    build_trace_related,
)

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
        f"destination system(s). "
        f"The highest observed severity is {highest_severity}."
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
    return build_trace_related(alerts, event_id)