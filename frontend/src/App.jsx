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
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [incidentStory, setIncidentStory] = useState(null);
  const [traceOverview, setTraceOverview] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [traceExplanation, setTraceExplanation] = useState(null);
  const [traceNextSteps, setTraceNextSteps] = useState([]);
  const [traceRelated, setTraceRelated] = useState([]);
  const [analystNotes, setAnalystNotes] = useState("");
  const [loading, setLoading] = useState(true);
  const [traceLoading, setTraceLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [focusMode, setFocusMode] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [alertsRes, summaryRes, timelineRes, storyRes, traceOverviewRes] =
        await Promise.all([
          fetch("http://127.0.0.1:8000/alerts"),
          fetch("http://127.0.0.1:8000/summary"),
          fetch("http://127.0.0.1:8000/timeline"),
          fetch("http://127.0.0.1:8000/incident-story"),
          fetch("http://127.0.0.1:8000/trace/overview"),
        ]);

      if (
        !alertsRes.ok ||
        !summaryRes.ok ||
        !timelineRes.ok ||
        !storyRes.ok ||
        !traceOverviewRes.ok
      ) {
        throw new Error("One or more backend routes failed");
      }

      const alertsData = await alertsRes.json();
      const summaryData = await summaryRes.json();
      const timelineData = await timelineRes.json();
      const storyData = await storyRes.json();
      const overviewData = await traceOverviewRes.json();

      setAlerts(alertsData);
      setSummary(summaryData);
      setTimeline(timelineData);
      setIncidentStory(storyData);
      setTraceOverview(overviewData);

      if (alertsData.length > 0) {
        const current =
          selectedAlert &&
          alertsData.find((a) => a.event_id === selectedAlert.event_id);

        setSelectedAlert(current || alertsData[0]);
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

  const loadTraceDetails = async (eventId) => {
    if (!eventId) return;
    setTraceLoading(true);

    try {
      const [explainRes, nextRes, relatedRes] = await Promise.all([
        fetch(`http://127.0.0.1:8000/trace/explain/${eventId}`),
        fetch(`http://127.0.0.1:8000/trace/next-steps/${eventId}`),
        fetch(`http://127.0.0.1:8000/trace/related/${eventId}`),
      ]);

      if (!explainRes.ok || !nextRes.ok || !relatedRes.ok) {
        throw new Error("Failed to load TRACE details");
      }

      const explainData = await explainRes.json();
      const nextData = await nextRes.json();
      const relatedData = await relatedRes.json();

      setTraceExplanation(explainData);
      setTraceNextSteps(nextData.next_steps || []);
      setTraceRelated(relatedData || []);
    } catch (err) {
      setTraceExplanation(null);
      setTraceNextSteps([]);
      setTraceRelated([]);
      console.error(err);
    } finally {
      setTraceLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedAlert?.event_id) {
      loadTraceDetails(selectedAlert.event_id);
    }
  }, [selectedAlert]);

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

  function safeFormatTimestamp(timestamp, pattern = "PPpp") {
    if (!timestamp) return "Unknown time";
    try {
      return format(parseISO(timestamp), pattern);
    } catch {
      return timestamp;
    }
  }

  const protocolOptions = useMemo(() => {
    return [...new Set(alerts.map((a) => a.proto).filter(Boolean))].sort();
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    let working = [...alerts];

    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      working = working.filter((alert) => {
        return [
          alert.signature,
          alert.src_ip,
          alert.dest_ip,
          alert.hostname,
          alert.url,
          alert.proto,
          alert.http_method,
          alert.event_id,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(q));
      });
    }

    if (severityFilter !== "all") {
      working = working.filter(
        (alert) => String(alert.severity ?? "") === severityFilter
      );
    }

    if (protocolFilter !== "all") {
      working = working.filter((alert) => alert.proto === protocolFilter);
    }

    if (focusMode && selectedAlert) {
      working = working.filter((alert) => {
        const sameSource =
          selectedAlert.src_ip && alert.src_ip === selectedAlert.src_ip;
        const sameDest =
          selectedAlert.dest_ip && alert.dest_ip === selectedAlert.dest_ip;
        const sameHost =
          selectedAlert.hostname &&
          alert.hostname &&
          alert.hostname === selectedAlert.hostname;

        return sameSource || sameDest || sameHost;
      });
    }

    return working;
  }, [alerts, searchTerm, severityFilter, protocolFilter, focusMode, selectedAlert]);

  const filteredTimeline = useMemo(() => {
    return timeline.filter((item) => {
      const match = filteredAlerts.find((a) => a.signature === item.event);
      return !!match;
    });
  }, [timeline, filteredAlerts]);

  const filteredSummary = useMemo(() => {
    const highSeverity = filteredAlerts.filter(
      (a) => Number(a.severity) >= 3
    ).length;

    const uniqueSources = new Set(
      filteredAlerts.map((a) => a.src_ip).filter(Boolean)
    ).size;

    const uniqueDestinations = new Set(
      filteredAlerts.map((a) => a.dest_ip).filter(Boolean)
    ).size;

    return {
      total_alerts: filteredAlerts.length,
      high_severity: highSeverity,
      unique_sources: uniqueSources,
      unique_destinations: uniqueDestinations,
    };
  }, [filteredAlerts]);

  const protocolChartData = useMemo(() => {
    return filteredAlerts.reduce((acc, alert) => {
      const proto = alert.proto || "UNKNOWN";
      const existing = acc.find((item) => item.proto === proto);
      if (existing) {
        existing.count += 1;
      } else {
        acc.push({ proto, count: 1 });
      }
      return acc;
    }, []);
  }, [filteredAlerts]);

  const focusedStory = useMemo(() => {
    if (!incidentStory) return null;

    if (!focusMode || !selectedAlert) {
      return incidentStory;
    }

    const filteredSteps =
      incidentStory.steps?.filter((step) => {
        const related = filteredAlerts.find((a) => a.signature === step.event);
        return !!related;
      }) || [];

    return {
      ...incidentStory,
      summary:
        "Focus Mode is active. TRACE is narrowing the incident story around the selected alert, prioritizing related source, destination, and host activity.",
      steps: filteredSteps,
      analyst_notes: [
        "Focus Mode is isolating activity related to the selected alert.",
        "Use this narrowed view to inspect progression around the chosen event.",
        "Compare the selected alert with adjacent related events for repeated indicators.",
      ],
    };
  }, [incidentStory, focusMode, selectedAlert, filteredAlerts]);

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
        <p>TRACE: Threat Reasoning and Analysis Copilot Engine</p>
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

      {traceOverview && (
        <section className="section">
          <h2>TRACE Overview</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <h3>Status</h3>
              <div className="value" style={{ fontSize: "1.4em" }}>
                {traceOverview.trace_status}
              </div>
            </div>
            <div className="stat-card">
              <h3>Priority</h3>
              <div className="value" style={{ fontSize: "1.3em" }}>
                {traceOverview.priority}
              </div>
            </div>
            <div className="stat-card">
              <h3>Risk Category</h3>
              <div className="value" style={{ fontSize: "1.15em" }}>
                {traceOverview.risk_category}
              </div>
            </div>
            <div className="stat-card">
              <h3>Active Alerts</h3>
              <div className="value">{traceOverview.active_incident_count}</div>
            </div>
            <div className="stat-card">
              <h3>Most Affected Source</h3>
              <div className="value" style={{ fontSize: "1.15em" }}>
                {traceOverview.most_affected_source}
              </div>
            </div>
            <div className="stat-card">
              <h3>Most Affected Destination</h3>
              <div className="value" style={{ fontSize: "1.15em" }}>
                {traceOverview.most_affected_destination}
              </div>
            </div>
          </div>

          <div
            className="event-item"
            style={{
              marginTop: "20px",
              borderLeft: "8px solid #00bfff",
              background: "rgba(0, 191, 255, 0.08)",
            }}
          >
            <div className="event-header">
              <span style={{ fontWeight: "bold", color: "#00bfff" }}>
                TRACE Guidance
              </span>
            </div>
            <p>{traceOverview.priority_message}</p>
            <div style={{ marginTop: "12px" }}>
              <strong>Top Risk Signature:</strong> {traceOverview.top_risk}
            </div>
          </div>
        </section>
      )}

      <section className="section">
        <h2>Investigation Controls</h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1fr 1fr",
            gap: "15px",
            marginBottom: "20px",
          }}
        >
          <input
            type="text"
            placeholder="Search by signature, IP, host, URL, protocol..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              padding: "14px",
              borderRadius: "10px",
              border: "2px solid #8b5cf6",
              background: "rgba(20, 20, 20, 0.8)",
              color: "white",
              fontSize: "1rem",
            }}
          />

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              padding: "14px",
              borderRadius: "10px",
              border: "2px solid #8b5cf6",
              background: "rgba(20, 20, 20, 0.8)",
              color: "white",
              fontSize: "1rem",
            }}
          >
            <option value="all">All Severities</option>
            <option value="1">Low</option>
            <option value="2">Medium</option>
            <option value="3">High</option>
            <option value="4">Critical</option>
          </select>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            style={{
              padding: "14px",
              borderRadius: "10px",
              border: "2px solid #8b5cf6",
              background: "rgba(20, 20, 20, 0.8)",
              color: "white",
              fontSize: "1rem",
            }}
          >
            <option value="all">All Protocols</option>
            {protocolOptions.map((proto) => (
              <option key={proto} value={proto}>
                {proto}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: "flex", gap: "15px", flexWrap: "wrap" }}>
          <button
            className="refresh-button"
            onClick={() => setFocusMode((prev) => !prev)}
            style={{
              background: focusMode
                ? "linear-gradient(135deg, #00bfff, #8b5cf6)"
                : "linear-gradient(135deg, #ff006e, #8b5cf6)",
              marginBottom: 0,
            }}
          >
            {focusMode ? "Disable Focus Mode" : "Enable Focus Mode"}
          </button>

          <button
            className="refresh-button"
            onClick={() => {
              setSearchTerm("");
              setSeverityFilter("all");
              setProtocolFilter("all");
              setFocusMode(false);
            }}
            style={{ marginBottom: 0 }}
          >
            Clear Filters
          </button>
        </div>

        {focusMode && selectedAlert && (
          <div
            style={{
              marginTop: "20px",
              padding: "18px",
              borderRadius: "12px",
              border: `2px solid ${getSeverityColor(selectedAlert.severity)}`,
              background: getSeverityBackground(selectedAlert.severity),
            }}
          >
            <strong>Focus Mode Active:</strong> TRACE is narrowing the dashboard to activity related to
            <span style={{ color: "#00bfff", marginLeft: "6px" }}>
              {selectedAlert.signature}
            </span>
            <div style={{ marginTop: "10px" }}>
              Related alerts currently visible: <strong>{filteredAlerts.length}</strong>
            </div>
          </div>
        )}

        <div style={{ marginTop: "20px" }}>
          <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>Severity Legend</h3>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {["1", "2", "3", "4"].map((sev) => (
              <span
                key={sev}
                style={{
                  padding: "8px 14px",
                  borderRadius: "999px",
                  fontWeight: 700,
                  color: "#111",
                  background: getSeverityColor(Number(sev)),
                }}
              >
                {getSeverityLabel(Number(sev))}
              </span>
            ))}
          </div>
        </div>
      </section>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Alerts</h3>
          <div className="value">{filteredSummary.total_alerts ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>High Severity</h3>
          <div className="value">{filteredSummary.high_severity ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>Unique Sources</h3>
          <div className="value">{filteredSummary.unique_sources ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>Unique Destinations</h3>
          <div className="value">{filteredSummary.unique_destinations ?? 0}</div>
        </div>
      </div>

      <section className="section">
        <h2>Attack Timeline</h2>
        <div className="timeline">
          {filteredTimeline.length === 0 ? (
            <p>No timeline events recorded yet</p>
          ) : (
            filteredTimeline.map((item, idx) => {
              const alertMatch = filteredAlerts.find((a) => a.signature === item.event);
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
        {!focusedStory ? (
          <p>No incident story available.</p>
        ) : (
          <>
            <div className="event-item" style={{ borderBottom: "none" }}>
              <div className="event-header">
                <span style={{ fontWeight: "bold", color: "#667eea" }}>
                  {focusedStory.title}
                </span>
              </div>
              <p style={{ marginTop: "10px" }}>{focusedStory.summary}</p>
            </div>

            <div style={{ marginTop: "20px" }}>
              {focusedStory.steps?.length > 0 ? (
                focusedStory.steps.map((step) => (
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
              {focusedStory.analyst_notes?.length > 0 ? (
                <ul style={{ paddingLeft: "20px" }}>
                  {focusedStory.analyst_notes.map((note, idx) => (
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
          {filteredAlerts.length === 0 ? (
            <p>No alerts detected yet</p>
          ) : (
            [...filteredAlerts].reverse().map((alert) => (
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
        <h2>TRACE Alert Analysis</h2>
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
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>
                TRACE Explanation
              </h3>
              {traceLoading ? (
                <p>TRACE is analyzing this alert...</p>
              ) : (
                <>
                  <p>{traceExplanation?.explanation || "No explanation available."}</p>
                  <div style={{ marginTop: "12px" }}>
                    <strong>Evidence:</strong>
                    <ul style={{ paddingLeft: "20px", marginTop: "8px" }}>
                      {(traceExplanation?.evidence || []).map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                </>
              )}
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>
                TRACE Next Steps
              </h3>
              {traceLoading ? (
                <p>TRACE is generating next steps...</p>
              ) : (
                <ul style={{ paddingLeft: "20px" }}>
                  {traceNextSteps.map((step, idx) => (
                    <li key={idx} style={{ marginBottom: "10px" }}>
                      {step}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>
                Related Activity
              </h3>
              {traceLoading ? (
                <p>TRACE is finding related activity...</p>
              ) : traceRelated.length === 0 ? (
                <p>No related activity found.</p>
              ) : (
                traceRelated.map((alert) => (
                  <div
                    key={alert.event_id}
                    className="event-item"
                    style={{
                      marginTop: "10px",
                      borderLeft: `6px solid ${getSeverityColor(alert.severity)}`,
                      background: getSeverityBackground(alert.severity),
                      cursor: "pointer",
                    }}
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <div className="event-header">
                      <span style={{ fontWeight: "bold", color: "#667eea" }}>
                        {alert.signature}
                      </span>
                      <span className="event-time">
                        {safeFormatTimestamp(alert.timestamp, "HH:mm:ss")}
                      </span>
                    </div>
                    <div className="event-meta">
                      <span>{alert.src_ip || "N/A"}</span>
                      <span>→</span>
                      <span>{alert.dest_ip || "N/A"}</span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div style={{ marginTop: "20px" }}>
              <h3 style={{ color: "#00bfff", marginBottom: "10px" }}>
                Analyst Notes
              </h3>
              <textarea
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                placeholder="Write analyst notes for this alert..."
                style={{
                  width: "100%",
                  minHeight: "120px",
                  padding: "14px",
                  borderRadius: "10px",
                  border: "2px solid #8b5cf6",
                  background: "rgba(20, 20, 20, 0.8)",
                  color: "white",
                  fontSize: "1rem",
                }}
              />
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;