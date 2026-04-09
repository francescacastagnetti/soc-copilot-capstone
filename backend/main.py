import json
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR.parent / "sample_data" / "eve.json"


def load_alerts():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    alerts = []
    for index, event in enumerate(raw_events, start=1):
        alerts.append(
            {
                "event_id": f"evt-{index:03}",
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


@app.get("/")
def root():
    return {"message": "SOC Copilot backend is running"}


@app.get("/alerts")
def get_alerts():
    return load_alerts()


@app.get("/alerts/{event_id}")
def get_alert(event_id: str):
    alerts = load_alerts()
    for alert in alerts:
        if alert["event_id"] == event_id:
            return alert
    return {"error": "Alert not found"}