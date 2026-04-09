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
    events = []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except:
                continue
    return events


def extract_alerts():
    raw_events = load_raw_events()
    alerts = []

    for i, event in enumerate(raw_events, start=1):
        if event.get("event_type") != "alert":
            continue

        alerts.append({
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
            "raw": event
        })

    return alerts


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
        "unique_destinations": unique_dests
    }


@app.get("/timeline")
def get_timeline():
    alerts = extract_alerts()

    sorted_alerts = sorted(
        alerts,
        key=lambda x: x["timestamp"] or ""
    )

    return [
        {
            "timestamp": a["timestamp"],
            "event": a["signature"],
            "src_ip": a["src_ip"],
            "dest_ip": a["dest_ip"]
        }
        for a in sorted_alerts
    ]