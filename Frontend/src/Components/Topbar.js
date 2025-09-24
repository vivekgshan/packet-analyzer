import React, { useEffect, useState, useRef } from "react";
import { useLocation } from "react-router-dom";
import { fetchProtocolCounts, fetchTraffic, fetchPackets } from "../Services/Api";

const pageTitles = {
  "/overview": { title: "Overview Dashboard", icon: "📊" },
  "/analytics": { title: "Traffic Analytics", icon: "📈" },
  "/Packetlogs": { title: "Detailed Packet Logs", icon: "📑" },
};

const Topbar = ({ onData }) => {
  const location = useLocation();
  const currentPage = pageTitles[location.pathname] || {
    title: "Network Packet Analysis",
    icon: "🛰️",
  };

  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [loadingBtn, setLoadingBtn] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true); 
  const intervalRef = useRef(null);

  const loadAll = async () => {
    try {
      const [c, t, p] = await Promise.all([
        fetchProtocolCounts(),
        fetchTraffic(),
        fetchPackets(),
      ]);
      onData?.({ counts: c, traffic: t, packets: p });
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Refresh failed:", err);
    }
  };

  const handleRefresh = async () => {
    setLoadingBtn(true);
    try {
      await loadAll();
    } finally {
      setLoadingBtn(false);
    }
  };

  useEffect(() => {
    if (autoRefresh) {
      loadAll(); 
      intervalRef.current = setInterval(loadAll, 30000);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh]);

  return (
    <div className="topbar">
      <div className="top-left">
        <h1>
          {currentPage.icon} {currentPage.title}
        </h1>
      </div>

      <div className="top-right">
        <span className="last-updated">
          Last updated:{" "}
          <span className="time-highlight">{lastUpdated.toLocaleTimeString()}</span>
        </span>

        <button
          className={`refresh-btn ${loadingBtn ? "loading" : ""}`}
          onClick={handleRefresh}
          disabled={loadingBtn}
        >
          {loadingBtn && <span className="spinner-mini" />}
          Refresh
        </button>

        <label className="switch">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={() => setAutoRefresh(!autoRefresh)}
          />
          <span className="slider round"></span>
        </label>
      </div>
    </div>
  );
};

export default Topbar;
