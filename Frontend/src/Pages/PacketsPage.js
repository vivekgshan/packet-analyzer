import React, { useState } from "react";
import { saveAs } from "file-saver";

const PacketTable = ({ packets = [] }) => {
  const [protocol, setProtocol] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 10;

  // Filtering
  const filtered = packets
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
    <div className="packet-browser">
      {/* Top bar: filters left, export right */}
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
            <option value="DNS">DNS</option>

          </select>
        </div>
        <button className="btn blue" onClick={exportCSV}>Export CSV</button>
      </div>

      {/* Table */}
      <div className="table-container">
        <table className="packet-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Protocol</th>
              <th>Src IP</th>
              <th>Dest IP</th>
              <th>Src Port</th>
              <th>Dest Port</th>
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
                <td>{p.srcPort}</td>
                <td>{p.destPort}</td>
                <td>{p.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
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
  );
};

export default PacketTable;
