import React from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = ["#3b82f6", "#22c55e", "#f97316", "#ef4444", "#8b5cf6", "#10b981", "#6366f1"];

const ProtocolPie = ({ counts }) => {
    const data = counts
      ? Object.entries(counts).map(([name, obj]) => ({
        name,
        value: obj.LIVE || 0,
        }))
      :[];


  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="card">
      <h4>Protocol Counts</h4>
      <ResponsiveContainer width="100%" height={340}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            outerRadius={110}
            label={false}
            labelLine={false}
          >
            {data.map((_, i) => (
              <Cell key={i} fill={COLORS[i % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip formatter={(value, name) => [`${value}`, `${name}`]} />
          <Legend
            verticalAlign="bottom"
            align="center"
            wrapperStyle={{ marginTop: "20px" }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ProtocolPie;
