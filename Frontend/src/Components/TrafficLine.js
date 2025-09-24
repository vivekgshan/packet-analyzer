import React from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";

const TrafficLine = ({ data }) => (
  <div className="card">
    <h4>Traffic Trend</h4>
    <ResponsiveContainer width="100%" height={450}>
      <LineChart
        data={data}
        margin={{ top: 20, right: 40, left: 20, bottom: 20}} 
      >
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis
          dataKey="time"
          tick={{ fill: "#0f0f10ff", fontSize: 12 }}
          angle={-25}
          textAnchor="end"
          height={70}
         minTickGap={40} 
         // padding={{ left: 0, right: 30 }} 
        />

        <YAxis
          allowDecimals={false}
          tick={{ fill: "#0f0f10ff", fontSize: 12 }}
        />

        <Tooltip
          labelStyle={{ color: "#000" }}
          contentStyle={{ backgroundColor: "#fff", borderRadius: "6px" }}
        />

        <Legend/>

        <Line
          type="monotone"
          dataKey="packets"
          stroke="#4a90e2"
          strokeWidth={2}
          dot={false}
          
        />
      </LineChart>
    </ResponsiveContainer>
  </div>
);

export default TrafficLine;
