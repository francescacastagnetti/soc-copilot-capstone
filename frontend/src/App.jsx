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
  const [incidentStory, setIncidentStory] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [alertsRes, summaryRes, timelineRes, storyRes] = await Promise.all([
        fetch("http://127.0.0.1:8000/alerts"),
        fetch("http://127.0.0.1:8000/summary"),
        fetch("http://127.0.0.1:8000/timeline"),
        fetch("http://127.0.0.1:8000/incident-story"),
      ]);

      if (!alertsRes.ok || !summaryRes.ok || !timelineRes.ok || !storyRes.ok) {
        throw new Error("One or more backend routes failed");
      }

      const alertsData = await alertsRes.json();
      const summaryData = await summaryRes.json();
      const timelineData = await timelineRes.json();
      const storyData = await storyRes.json();

      setAlerts(alertsData);
      setSummary(summaryData);
      setTimeline(timelineData);
      setIncidentStory(storyData);

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

  function getSeverityColor(severity) {
    const sev = Number(severity);
    if (sev >= 4) return "#ff4d4f";
    if (sev === 3) return "#fa8c16";
    if (sev === 2) return "#fadb14";
    return "#52c41a";
  }

  function getSeverityLabel(severity) {
    const sev = Number(severity);
    if (sev >= 4) return "Critical";
    if (sev === 3) return "High";
    if (sev === 2) return "Medium";
    return "Low";
  }

  function getSeverityBackground(severity) {
    const sev = Number(severity);
    if (sev >= 4) return "rgba(255, 77, 79, 0.12)";
    if (sev === 3) return "rgba(250, 140, 22, 0.12)";
    if (sev === 2) return "rgba(250, 219, 20, 0.10)";
    return "rgba(82, 196, 26, 0.10)";
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

      <section className="section">
        <h2>Attack Timeline</h2>
        <div className="timeline">
          {timeline.length === 0 ? (
            <p>No timeline events recorded yet</p>
          ) : (
            timeline.map((item, idx) => {
              const alertMatch = alerts.find((a) => a.signature === item.event);
              const severity = alertMatch?.severity ?? 1;

              return (
                <div
                  key={idx}
                  className="timeline-item"
                  style={{
                    borderLeft: `8px solid ${getSeverityColor(severity)}`,
                    background: getSeverityBackground(severity),
                    cursor: "pointer",
                  }}
                  onClick={() => {
                    if (alertMatch) setSelectedAlert(alertMatch);
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
        <h2>Incident Story</h2>
        {!incidentStory ? (
          <p>No incident story available.</p>
        ) : (
          <>
            <div className="event-item" style={{ borderBottom: "none" }}>
              <div className="event-header">
                <span style={{ fontWeight: "bold", color: "#667eea" }}>
                  {incidentStory.title}
                </span>
              </div>
              <p style={{ marginTop: "10px" }}>{incidentStory.summary}</p>
            </div>

            <div style={{ marginTop: "20px" }}>
              {incidentStory.steps?.length > 0 ? (
                incidentStory.steps.map((step) => (
                  <div
                    key={step.step_number}
                    className="event-item"
                    style={{
                      borderLeft: `8px solid ${getSeverityColor(step.severity)}`,
                      background: getSeverityBackground(step.severity),
                    }}
                  >
                    <div className="event-header">
                      <span style={{ fontWeight: "bold", color: "#00bfff" }}>
                        Step {step.step_number}
                      </span>
                      <span className="event-time">
                        {safeFormatTimestamp(step.timestamp, "HH:mm:ss")}
                      </span>
                    </div>
                    <div className="event-url">{step.event}</div>
                    <p style={{ marginTop: "10px" }}>{step.description}</p>
                  </div>
                ))
              ) : (
                <p>No incident steps available.</p>
              )}
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>Analyst Notes</h3>
              {incidentStory.analyst_notes?.length > 0 ? (
                <ul style={{ paddingLeft: "20px" }}>
                  {incidentStory.analyst_notes.map((note, idx) => (
                    <li key={idx} style={{ marginBottom: "10px" }}>
                      {note}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No analyst notes available.</p>
              )}
            </div>
          </>
        )}
      </section>

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
                  borderLeft: `8px solid ${getSeverityColor(alert.severity)}`,
                  background: getSeverityBackground(alert.severity),
                  boxShadow:
                    selectedAlert?.event_id === alert.event_id
                      ? `0 0 20px ${getSeverityColor(alert.severity)}55`
                      : undefined,
                }}
              >
                <div className="event-header">
                  <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
                    <span className="event-method">{alert.proto || "N/A"}</span>
                    <span
                      style={{
                        padding: "4px 10px",
                        borderRadius: "999px",
                        fontWeight: 700,
                        fontSize: "0.85rem",
                        color: "#111",
                        background: getSeverityColor(alert.severity),
                      }}
                    >
                      {getSeverityLabel(alert.severity)}
                    </span>
                  </div>

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
          <div
            className="event-item"
            style={{
              border: `3px solid ${getSeverityColor(selectedAlert.severity)}`,
              background: getSeverityBackground(selectedAlert.severity),
              boxShadow: `0 0 24px ${getSeverityColor(selectedAlert.severity)}44`,
            }}
          >
            <div className="event-header">
              <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
                <span style={{ fontWeight: "bold", color: "#667eea" }}>
                  {selectedAlert.signature}
                </span>
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: "999px",
                    fontWeight: 700,
                    fontSize: "0.85rem",
                    color: "#111",
                    background: getSeverityColor(selectedAlert.severity),
                  }}
                >
                  {getSeverityLabel(selectedAlert.severity)}
                </span>
              </div>

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
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>Explanation</h3>
              <p>{explainAlert(selectedAlert)}</p>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;