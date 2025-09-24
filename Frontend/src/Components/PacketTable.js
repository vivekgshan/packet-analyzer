import React, { useState } from "react";
import { saveAs } from "file-saver";

const PacketTable = ({ packets = [] }) => {
  const [protocol, setProtocol] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 10;

  // Normalize API response
  const normalizePackets = (packets) =>
    packets.map((p) => {
      const match = p.summary?.match(/:(\d+)\s*>\s*.*?:(\d+)/);
      return {
        id: p.id,
        timestamp: p.timestamp,
        protocol: p.protocol,
        srcIP: p.src_ip,
        destIP: p.dst_ip,
        srcPort: match ? match[1] : "",
        destPort: match ? match[2] : "",
        length: p.length || "",
        anomaly: p.anomaly || false,
      };
    });

  const normalizedPackets = normalizePackets(packets);

  // Filtering
  const filtered = normalizedPackets
    .filter((p) => (protocol ? p.protocol === protocol : true))
    .filter((p) => {
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return (
        p.protocol.toLowerCase().includes(q) ||
        p.srcIP.toLowerCase().includes(q) ||
        p.destIP.toLowerCase().includes(q)
      );
    });

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageData = filtered.slice(page * pageSize, page * pageSize + pageSize);

  // Export CSV
  const exportCSV = () => {
    const rows = [
      ["ID", "Timestamp", "Protocol", "SrcIP", "DestIP", "SrcPort", "DestPort", "Length"],
      ...filtered.map((p) => [
        p.id,
        new Date(p.timestamp).toLocaleString(),
        p.protocol,
        p.srcIP,
        p.destIP,
        p.srcPort,
        p.destPort,
        p.length,
      ]),
    ];
    const csv = rows.map((r) => r.join(",")).join("\n");
    saveAs(new Blob([csv], { type: "text/csv;charset=utf-8;" }), "packets.csv");
  };

  return (
    <div>
      <h3 className="section-title">Packet Browser</h3>

      <div className="card packet-card">
        <div className="table-top">
          <div className="table-filters">
            <input
              placeholder="Search..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
            />
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="HTTP">HTTP</option>
              <option value="HTTPS">HTTPS</option>
              <option value="DNS">DNS</option>
              <option value="FTP">FTP</option>
              <option value="SSH">SSH</option>
            </select>
          </div>
          <button className="btn blue" onClick={exportCSV}>Export CSV</button>
        </div>

        <div className="table-container">
          <table className="packet-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Protocol</th>
                <th>Src IP</th>
                <th>Dest IP</th>
                {/* <th>Src Port</th>
                <th>Dest Port</th> */}
                <th>Length</th>
              </tr>
            </thead>
            <tbody>
              {pageData.map((p) => (
                <tr key={p.id} className={p.anomaly ? "anomaly-row" : ""}>
                  <td>{p.id}</td>
                  <td>{new Date(p.timestamp).toLocaleString()}</td>
                  <td><span className={`badge ${p.protocol.toLowerCase()}`}>{p.protocol}</span></td>
                  <td>{p.srcIP}</td>
                  <td>{p.destIP}</td>
                  {/* <td>{p.srcPort}</td>
                  <td>{p.destPort}</td> */}
                  <td>{'-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="pagination">
          <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
            Prev
          </button>
          <span>Page {page + 1} of {totalPages}</span>
          <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>
            Next
          </button>
        </div>
      </div>
    </div>
  );
};

export default PacketTable;
