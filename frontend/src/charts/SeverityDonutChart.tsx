import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface Props {
  data: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export const SeverityDonutChart: React.FC<Props> = ({ data }) => {
  const chartData = [
    { name: "Critical", value: data.critical || 0, color: "#EF4444" },
    { name: "High", value: data.high || 0, color: "#F97316" },
    { name: "Medium", value: data.medium || 0, color: "#EAB308" },
    { name: "Low", value: data.low || 0, color: "#10B981" },
    { name: "Info", value: data.info || 0, color: "#3B82F6" },
  ].filter(d => d.value > 0);

  const total = Object.values(data).reduce((a, b) => a + b, 0);

  if (total === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-xs text-slate-500 font-mono">
        No active vulnerabilities detected
      </div>
    );
  }

  return (
    <div className="relative h-52 w-full flex items-center justify-center">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={75}
            paddingAngle={4}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} stroke="#0B0F19" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: "#111827", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
            itemStyle={{ color: "#F8FAFC" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-2xl font-extrabold text-white font-mono">{total}</span>
        <span className="text-[10px] text-slate-400 uppercase tracking-wider">Findings</span>
      </div>
    </div>
  );
};
