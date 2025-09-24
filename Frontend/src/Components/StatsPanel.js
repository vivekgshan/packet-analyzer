import React from "react";
import { exportPDFFromNode, shareJSON } from "./ExportButton";
import { saveAs } from "file-saver";

const StatsPanel = ({ packets = [], counts = {} }) => {
  const total = packets.length;
  const avgSize = total
    ? (packets.reduce((a, b) => a + b.length, 0) / total).toFixed(0)
    : 0;

  // Export CSV
  const exportCSV = () => {
    const rows = [
      ["ID", "Timestamp", "Protocol", "SrcIP", "DestIP", "SrcPort", "DestPort", "Length"],
      ...packets.map((p) => [
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
    <aside className="stats-panel">
      <h3>Statistics</h3>
      <div className="stat-cards">
        <div className="stat-item">
          <span className="icon">📊</span>
          <div>
            <p>Total Packets</p>
            <b>{total}</b>
          </div>
        </div>
        <div className="stat-item">
          <span className="icon">📏</span>
          <div>
            <p>Avg Size</p>
            <b>{avgSize} bytes</b>
          </div>
        </div>
        <div className="stat-item">
          <span className="icon">⚡</span>
          <div>
            <p>Capture Rate</p>
            <b>0.3 pkt/sec</b>
          </div>
        </div>
        <div className="stat-item">
          <span className="icon">🔴</span>
          <div>
            <p>Live Count</p>
            <b>{total}</b>
          </div>
        </div>
      </div>

      <div className="management-tools card">
        <h4>Management Tools</h4>
        <p>Export captured packets in CSV / JSON / PDF</p>
        <div className="export-btns">
          <button className="btn blue" onClick={exportCSV}>Export CSV</button>
          <button className="btn teal" onClick={() => shareJSON(packets)}>Export JSON</button>
          <button className="btn purple" onClick={() => exportPDFFromNode("packetTable")}>Export PDF</button>
        </div>
      </div>
    </aside>
  );
};

export default StatsPanel;
