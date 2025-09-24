import React from "react";
import { NavLink } from "react-router-dom";

const Sidebar = () => (
  <aside className="sidebar" aria-label="Main navigation">
    <div className="brand">
      <div className="logo">🛰️</div>
      <div className="brand-title">Packet Analyzer</div>
    </div>

    <nav>
      <ul>
        <li>
          <NavLink to="/overview" className={({ isActive }) => isActive ? "nav-active" : ""}>
            <span className="nav-icon">📊</span> Overview
          </NavLink>
        </li>
        <li>
          <NavLink to="/analytics" className={({ isActive }) => isActive ? "nav-active" : ""}>
            <span className="nav-icon">📈</span> Analytics
          </NavLink>
        </li>
        <li>
          <NavLink to="/Packetlogs" className={({ isActive }) => isActive ? "nav-active" : ""}>
            <span className="nav-icon">📑</span> Packet Logs
          </NavLink>
        </li>
     
      </ul>
    </nav>
  </aside>
);

export default Sidebar;
