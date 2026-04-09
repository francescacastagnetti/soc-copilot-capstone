import { useEffect, useState } from "react";
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
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [alertsRes, summaryRes, timelineRes] = await Promise.all([
        fetch("http://127.0.0.1:8000/alerts"),
        fetch("http://127.0.0.1:8000/summary"),
        fetch("http://127.0.0.1:8000/timeline"),
      ]);

      if (!alertsRes.ok || !summaryRes.ok || !timelineRes.ok) {
        throw new Error("One or more backend routes failed");
      }

      const alertsData = await alertsRes.json();
      const summaryData = await summaryRes.json();
      const timelineData = await timelineRes.json();

      setAlerts(alertsData);
      setSummary(summaryData);
      setTimeline(timelineData);

      if (alertsData.length > 0) {
        setSelectedAlert((prev) => {
          if (!prev) return alertsData[0];
          return alertsData.find((a) => a.event_id === prev.event_id) || alertsData[0];
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

  // 🔥 NEW: severity color function
  function getSeverityColor(severity) {
    if (severity >= 4) return "#ff4d4f";
    if (severity === 3) return "#fa8c16";
    if (severity === 2) return "#fadb14";
    return "#52c41a";
  }

  const protocolChartData = alerts.reduce((acc, alert) => {
    const proto = alert.proto || "UNKNOWN";
    const existing = acc.find((item) => item.proto === proto);
    if (existing) {
      existing.count += 1;
    } else {
      acc.push({ proto, count: 1 });
    }
    return acc;
  }, []);

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

      {/* STATS */}
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Alerts</h3>
          <div className="value">{summary?.total_alerts ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>High Severity</h3>
          <div className="value">{summary?.high_severity ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>Unique Sources</h3>
          <div className="value">{summary?.unique_sources ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>Unique Destinations</h3>
          <div className="value">{summary?.unique_destinations ?? 0}</div>
        </div>
      </div>

      {/* TIMELINE */}
      <section className="section">
        <h2>Attack Timeline</h2>
        <div className="timeline">
          {timeline.length === 0 ? (
            <p>No timeline events recorded yet</p>
          ) : (
            timeline.map((item, idx) => {
              const alertMatch = alerts.find(a => a.signature === item.event);
              return (
                <div
                  key={idx}
                  className="timeline-item"
                  style={{
                    borderLeft: `4px solid ${getSeverityColor(alertMatch?.severity)}`
                  }}
                >
                  <span className="timeline-time">
                    {safeFormatTimestamp(item.timestamp)}
                  </span>
                  <span className="timeline-event">{item.event}</span>
                </div>
              );
            })
          )}
        </div>
      </section>

      {/* CHART */}
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

      {/* ALERT LIST */}
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
                style={{
                  cursor: "pointer",
                  borderLeft: `5px solid ${getSeverityColor(alert.severity)}`
                }}
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

      {/* COPILOT */}
      <section className="section">
        <h2>Copilot Alert Analysis</h2>
        {!selectedAlert ? (
          <p>Select an alert to inspect its details.</p>
        ) : (
          <div
            className="event-item"
            style={{
              border: `2px solid ${getSeverityColor(selectedAlert.severity)}`
            }}
          >
            <div className="event-header">
              <span style={{ fontWeight: "bold", color: "#667eea" }}>
                {selectedAlert.signature}
              </span>
              <span className="event-time">
                {safeFormatTimestamp(selectedAlert.timestamp, "HH:mm:ss")}
              </span>
            </div>

            <div className="event-meta" style={{ flexWrap: "wrap" }}>
              <span>Source IP: {selectedAlert.src_ip}</span>
              <span>Destination IP: {selectedAlert.dest_ip}</span>
              <span>Protocol: {selectedAlert.proto}</span>
              <span>Severity: {selectedAlert.severity}</span>
              <span>Host: {selectedAlert.hostname}</span>
              <span>URL: {selectedAlert.url}</span>
              <span>Method: {selectedAlert.http_method}</span>
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ color: "#00bfff" }}>Explanation</h3>
              <p>{explainAlert(selectedAlert)}</p>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;