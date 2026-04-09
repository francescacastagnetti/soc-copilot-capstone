import { useEffect, useState } from "react";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/alerts")
      .then((res) => res.json())
      .then((data) => {
        setAlerts(data);
        if (data.length > 0) {
          setSelectedAlert(data[0]);
        }
      })
      .catch((err) => console.error("Error fetching alerts:", err));
  }, []);

  function explainAlert(alert) {
    return `This alert fired because traffic from ${alert.src_ip} to ${alert.dest_ip} matched the signature "${alert.signature}". The request used ${alert.http_method} to ${alert.url} on ${alert.hostname}.`;
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial, sans-serif" }}>
      <h1 style={{ textAlign: "center" }}>SOC Copilot Dashboard</h1>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: "2rem",
          alignItems: "start",
          marginTop: "2rem",
        }}
      >
        <div>
          <h2>Alerts</h2>
          {alerts.length === 0 ? (
            <p>Loading...</p>
          ) : (
            <table
              border="1"
              cellPadding="10"
              style={{ width: "100%", borderCollapse: "collapse" }}
            >
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Signature</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.event_id}
                    onClick={() => setSelectedAlert(alert)}
                    style={{
                      cursor: "pointer",
                      backgroundColor:
                        selectedAlert?.event_id === alert.event_id ? "#eef3ff" : "white",
                    }}
                  >
                    <td>{alert.event_id}</td>
                    <td>{alert.signature}</td>
                    <td>{alert.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div>
          <h2>Details</h2>
          {!selectedAlert ? (
            <p>Click an alert</p>
          ) : (
            <>
              <p>
                <b>Timestamp:</b> {selectedAlert.timestamp}
              </p>
              <p>
                <b>Source:</b> {selectedAlert.src_ip}
              </p>
              <p>
                <b>Dest:</b> {selectedAlert.dest_ip}
              </p>
              <p>
                <b>Protocol:</b> {selectedAlert.proto}
              </p>
              <p>
                <b>Signature:</b> {selectedAlert.signature}
              </p>
              <p>
                <b>Severity:</b> {selectedAlert.severity}
              </p>
              <p>
                <b>Host:</b> {selectedAlert.hostname}
              </p>
              <p>
                <b>URL:</b> {selectedAlert.url}
              </p>
              <p>
                <b>Method:</b> {selectedAlert.http_method}
              </p>

              <h3>Explanation</h3>
              <p>{explainAlert(selectedAlert)}</p>
            </>
          )}
        </div>

        <div>
          <h2>Timeline</h2>
          {alerts.length === 0 ? (
            <p>No events found.</p>
          ) : (
            <ul style={{ paddingLeft: "1.2rem" }}>
              {alerts.map((alert) => (
                <li key={alert.event_id} style={{ marginBottom: "1rem" }}>
                  <div>
                    <b>{alert.timestamp}</b>
                  </div>
                  <div>{alert.signature}</div>
                  <div style={{ fontSize: "0.95rem", color: "#555" }}>
                    {alert.src_ip} → {alert.dest_ip}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;