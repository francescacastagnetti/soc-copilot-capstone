import { useEffect, useMemo, useState } from "react";
import { format, parseISO } from "date-fns";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("http://127.0.0.1:8000/alerts");

      if (!res.ok) {
        throw new Error(`Backend returned ${res.status}`);
      }

      const data = await res.json();
      setAlerts(data);

      if (data.length > 0) {
        setSelectedAlert((prev) => {
          if (!prev) return data[0];
          return data.find((a) => a.event_id === prev.event_id) || data[0];
        });
      } else {
        setSelectedAlert(null);
      }

      setLastUpdate(new Date());
    } catch (err) {
      setError("Failed to load data: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const summary = useMemo(() => {
    const uniqueUrls = new Set(alerts.map((a) => a.url).filter(Boolean)).size;
    const uniqueSources = new Set(alerts.map((a) => a.src_ip).filter(Boolean)).size;
    const highSeverity = alerts.filter((a) => Number(a.severity) >= 3).length;

    return {
      totalAlerts: alerts.length,
      highSeverity,
      uniqueUrls,
      uniqueSources,
    };
  }, [alerts]);

  const protocolChartData = useMemo(() => {
    const counts = alerts.reduce((acc, alert) => {
      const proto = alert.proto || "UNKNOWN";
      acc[proto] = (acc[proto] || 0) + 1;
      return acc;
    }, {});

    return Object.entries(counts).map(([proto, count]) => ({
      proto,
      count,
    }));
  }, [alerts]);

  const timelineData = useMemo(() => {
    return [...alerts].sort((a, b) => {
      const aTime = new Date(a.timestamp || 0).getTime();
      const bTime = new Date(b.timestamp || 0).getTime();
      return aTime - bTime;
    });
  }, [alerts]);

  function explainAlert(alert) {
    if (!alert) return "";

    const src = alert.src_ip || "unknown source";
    const dst = alert.dest_ip || "unknown destination";
    const sig = alert.signature || "unknown alert";
    const method = alert.http_method || "unknown method";
    const host = alert.hostname || "unknown host";
    const url = alert.url || "/";

    return `Traffic from ${src} to ${dst} triggered the alert "${sig}". The observed request used ${method} against ${host}${url}. This event should be reviewed as part of the analyst investigation workflow.`;
  }

  function safeFormatTimestamp(timestamp, pattern = "PPpp") {
    if (!timestamp) return "Unknown time";
    try {
      return format(parseISO(timestamp), pattern);
    } catch {
      return timestamp;
    }
  }

  if (loading && alerts.length === 0) {
    return (
      <div className="dashboard">
        <div className="loading">Loading dashboard data...</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="header">
        <h1>SOC Copilot Dashboard</h1>
        <p>Real-time attack monitoring and AI-assisted analyst support</p>
        {lastUpdate && (
          <p style={{ fontSize: "0.9em", color: "#999", marginTop: "10px" }}>
            Last updated: {format(lastUpdate, "PPpp")}
          </p>
        )}
      </header>

      <button onClick={loadData} className="refresh-button" disabled={loading}>
        {loading ? "Refreshing..." : "Refresh Data"}
      </button>

      {error && (
        <div className="error">
          <h3>Error</h3>
          <p>{error}</p>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Alerts</h3>
          <div className="value">{summary.totalAlerts}</div>
        </div>
        <div className="stat-card">
          <h3>High Severity</h3>
          <div className="value">{summary.highSeverity}</div>
        </div>
        <div className="stat-card">
          <h3>Unique URLs</h3>
          <div className="value">{summary.uniqueUrls}</div>
        </div>
        <div className="stat-card">
          <h3>Unique Sources</h3>
          <div className="value">{summary.uniqueSources}</div>
        </div>
      </div>

      <section className="section">
        <h2>Attack Timeline</h2>
        <div className="timeline">
          {timelineData.length === 0 ? (
            <p>No alert events recorded yet</p>
          ) : (
            timelineData.map((alert) => (
              <div
                key={alert.event_id}
                className="timeline-item"
                onClick={() => setSelectedAlert(alert)}
                style={{ cursor: "pointer" }}
              >
                <span className="timeline-time">
                  {safeFormatTimestamp(alert.timestamp)}
                </span>
                <span className="timeline-event">{alert.signature}</span>
              </div>
            ))
          )}
        </div>
      </section>

      {protocolChartData.length > 0 && (
        <section className="section">
          <h2>Protocol Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={protocolChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="proto" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#667eea" />
            </BarChart>
          </ResponsiveContainer>
        </section>
      )}

      <section className="section">
        <h2>Detected Alerts</h2>
        <div className="events-list">
          {alerts.length === 0 ? (
            <p>No alerts detected yet</p>
          ) : (
            [...alerts].reverse().map((alert) => (
              <div
                key={alert.event_id}
                className="event-item"
                onClick={() => setSelectedAlert(alert)}
                style={{ cursor: "pointer" }}
              >
                <div className="event-header">
                  <span className="event-method">{alert.proto || "N/A"}</span>
                  <span className="event-time">
                    {safeFormatTimestamp(alert.timestamp, "HH:mm:ss")}
                  </span>
                </div>

                <div className="event-url">{alert.signature}</div>

                <div className="event-meta">
                  <span>Source: {alert.src_ip || "N/A"}</span>
                  <span>Destination: {alert.dest_ip || "N/A"}</span>
                  <span>Severity: {alert.severity ?? "N/A"}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="section">
        <h2>Copilot Alert Analysis</h2>
        {!selectedAlert ? (
          <p>Select an alert to inspect its details.</p>
        ) : (
          <div className="event-item" style={{ borderBottom: "none" }}>
            <div className="event-header">
              <span style={{ fontWeight: "bold", color: "#667eea" }}>
                {selectedAlert.signature}
              </span>
              <span className="event-time">
                {safeFormatTimestamp(selectedAlert.timestamp, "HH:mm:ss")}
              </span>
            </div>

            <div className="event-meta" style={{ flexWrap: "wrap" }}>
              <span>Source IP: {selectedAlert.src_ip || "N/A"}</span>
              <span>Destination IP: {selectedAlert.dest_ip || "N/A"}</span>
              <span>Protocol: {selectedAlert.proto || "N/A"}</span>
              <span>Severity: {selectedAlert.severity ?? "N/A"}</span>
              <span>Host: {selectedAlert.hostname || "N/A"}</span>
              <span>URL: {selectedAlert.url || "N/A"}</span>
              <span>Method: {selectedAlert.http_method || "N/A"}</span>
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ marginBottom: "10px", color: "#00bfff" }}>
                Plain-English Explanation
              </h3>
              <p>{explainAlert(selectedAlert)}</p>
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ marginBottom: "10px", color: "#00bfff" }}>
                Raw Event
              </h3>
              <pre
                style={{
                  background: "rgba(0,0,0,0.35)",
                  padding: "15px",
                  borderRadius: "10px",
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                }}
              >
                {JSON.stringify(selectedAlert.raw, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;