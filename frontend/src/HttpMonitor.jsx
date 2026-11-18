import { useEffect, useState } from "react";

import {
  subscribeHttpMonitor,
  clearHttpRequests
} from "./httpMonitor";

export default function HttpMonitor() {
  const [requests, setRequests] = useState([]);

  useEffect(() => {
    return subscribeHttpMonitor(setRequests);
  }, []);

  return (
    <section className="http-monitor">
      <div className="monitor-header">
        <h3>HTTP Monitor</h3>

        <button onClick={clearHttpRequests}>
          Clear
        </button>
      </div>

      <div className="monitor-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Method</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>Duration</th>
            </tr>
          </thead>

          <tbody>
            {requests.length === 0 ? (
              <tr>
                <td colSpan="5">
                  No HTTP requests yet
                </td>
              </tr>
            ) : (
              requests.map((request) => (
                <tr key={request.id}>
                  <td>{request.timestamp}</td>
                  <td>{request.method}</td>
                  <td>{request.url}</td>

                  <td
                    className={
                      request.status < 400
                        ? "monitor-success"
                        : "monitor-error"
                    }
                  >
                    {request.status}
                  </td>

                  <td>{request.duration} ms</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
