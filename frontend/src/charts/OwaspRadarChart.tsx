import React from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

interface Props {
  vulnerabilities: any[];
}

export const OwaspDistributionChart: React.FC<Props> = ({ vulnerabilities }) => {
  const categories: Record<string, number> = {
    "A01 Broken Access": 0,
    "A02 Misconfig": 0,
    "A03 Supply Chain": 0,
    "A04 Crypto": 0,
    "A05 Injection": 0,
    "A06 Insecure Design": 0,
    "A07 Auth Failure": 0,
    "A08 Integrity": 0,
    "A09 Logging": 0,
    "A10 Exceptions": 0,
  };

  vulnerabilities.forEach(v => {
    const cat = v.owasp_category || "";
    if (cat.includes("A01")) categories["A01 Broken Access"]++;
    else if (cat.includes("A02")) categories["A02 Misconfig"]++;
    else if (cat.includes("A03")) categories["A03 Supply Chain"]++;
    else if (cat.includes("A04")) categories["A04 Crypto"]++;
    else if (cat.includes("A05")) categories["A05 Injection"]++;
    else if (cat.includes("A06")) categories["A06 Insecure Design"]++;
    else if (cat.includes("A07")) categories["A07 Auth Failure"]++;
    else if (cat.includes("A08")) categories["A08 Integrity"]++;
    else if (cat.includes("A09")) categories["A09 Logging"]++;
    else if (cat.includes("A10")) categories["A10 Exceptions"]++;
    else categories["A02 Misconfig"]++;
  });

  const data = Object.entries(categories).map(([name, count]) => ({
    name,
    count,
  }));

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 5 }}>
          <XAxis type="number" stroke="#64748B" fontSize={11} />
          <YAxis dataKey="name" type="category" stroke="#94A3B8" fontSize={10} width={110} />
          <Tooltip
            contentStyle={{ backgroundColor: "#111827", borderColor: "#1E293B", borderRadius: "8px", fontSize: "12px" }}
            itemStyle={{ color: "#06B6D4" }}
          />
          <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.count > 0 ? "#06B6D4" : "#1E293B"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export const SecurityScoreGauge: React.FC<{ score: number; riskLevel?: string }> = ({ score, riskLevel }) => {
  const rounded = Math.round(score);
  const color = rounded >= 85 ? "text-emerald-400" : rounded >= 65 ? "text-amber-400" : "text-rose-400";
  const strokeColor = rounded >= 85 ? "#10B981" : rounded >= 65 ? "#EAB308" : "#EF4444";
  const strokeDashoffset = 251.2 - (251.2 * rounded) / 100;

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative w-36 h-36 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90">
          <circle
            cx="72"
            cy="72"
            r="48"
            className="text-slate-800"
            strokeWidth="10"
            stroke="currentColor"
            fill="transparent"
          />
          <circle
            cx="72"
            cy="72"
            r="48"
            stroke={strokeColor}
            strokeWidth="10"
            strokeDasharray={301.6}
            strokeDashoffset={301.6 - (301.6 * rounded) / 100}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-extrabold font-mono ${color}`}>{rounded}</span>
          <span className="text-[10px] text-slate-400 tracking-wider">/ 100</span>
        </div>
      </div>
      <div className="text-center mt-2">
        <div className="text-xs font-semibold text-white tracking-wide">{riskLevel || "Calculated Posture"}</div>
        <div className="text-[10px] text-slate-400 mt-0.5">Automated Risk Index</div>
      </div>
    </div>
  );
};
