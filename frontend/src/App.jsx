import { useEffect, useState } from "react";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/alerts")
      .then((res) => res.json())
      .then((data) => setAlerts(data))
      .catch((err) => console.error("Error fetching alerts:", err));
  }, []);

  function explainAlert(alert) {
    return `This alert fired because traffic from ${alert.src_ip} to ${alert.dest_ip} matched the signature "${alert.signature}". The request used ${alert.http_method} to ${alert.url} on ${alert.hostname}.`;
  }

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial, sans-serif" }}>
      <h1>SOC Copilot Dashboard</h1>

      <div style={{ display: "flex", gap: "2rem" }}>
        <div style={{ flex: 1 }}>
          <h2>Alerts</h2>
          {alerts.length === 0 ? (
            <p>Loading...</p>
          ) : (
            <table border="1" cellPadding="8">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Signature</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.event_id} onClick={() => setSelectedAlert(alert)}>
                    <td>{alert.event_id}</td>
                    <td>{alert.signature}</td>
                    <td>{alert.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div style={{ flex: 1 }}>
          <h2>Details</h2>
          {!selectedAlert ? (
            <p>Click an alert</p>
          ) : (
            <>
              <p><b>Source:</b> {selectedAlert.src_ip}</p>
              <p><b>Dest:</b> {selectedAlert.dest_ip}</p>
              <p><b>Signature:</b> {selectedAlert.signature}</p>

              <h3>Explanation</h3>
              <p>{explainAlert(selectedAlert)}</p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;