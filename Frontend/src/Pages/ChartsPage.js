import React, { useState } from "react";
import Sidebar from "../Components/Sidebar";
import Topbar from "../Components/Topbar";
import ProtocolPie from "../Components/ProtocolPie";
import TrafficLine from "../Components/TrafficLine";
import Loader from "../Components/Loader";

const ChartsPage = () => {
  const [counts, setCounts] = useState({});
  const [traffic, setTraffic] = useState([]);
  const [loading, setLoading] = useState(true);

  return (
    <div className="app-root">
      <Sidebar />
      <div className="main-pane">
        <Topbar
          onData={({ counts, traffic }) => {
            if (counts) setCounts(counts);
            if (traffic) setTraffic(traffic);
            setLoading(false);
          }}
        />
        <main className="main-content">
          {loading ? (
            <Loader />
          ) : (
            <section className="charts-grid" style={{ display: "flex", flexDirection: "column", gap: "2rem" }}>
              <div className="card">
                <ProtocolPie counts={counts} />
              </div>
              <div className="card">
                <TrafficLine data={traffic} />
              </div>
            </section>
          )}
        </main>
      </div>
    </div>
  );
};

export default ChartsPage;
