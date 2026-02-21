import { Sparkles, AlertTriangle, Loader2 } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

interface RiskBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  clean: number;
}

interface AISummaryCardProps {
  summary: string | null;
  riskBreakdown: RiskBreakdown | null;
  loading: boolean;
}

const RISK_COLORS = [
  { key: "critical", color: "hsl(0 80% 55%)", label: "Critical" },
  { key: "high", color: "hsl(22 90% 50%)", label: "High" },
  { key: "medium", color: "hsl(45 90% 52%)", label: "Medium" },
  { key: "low", color: "hsl(160 60% 42%)", label: "Low" },
  { key: "clean", color: "hsl(220 12% 38%)", label: "Clean" },
];

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload?.length) {
    return (
      <div className="glass-panel rounded-lg p-3 border" style={{ borderColor: "hsl(var(--rust) / 0.3)" }}>
        <p className="font-display text-base" style={{ color: payload[0].payload.fill }}>
          {payload[0].name}
        </p>
        <p className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
          {payload[0].value} files
        </p>
      </div>
    );
  }
  return null;
};

const CustomLegend = ({ payload }: any) => (
  <div className="flex flex-wrap gap-x-4 gap-y-1.5 mt-3 justify-center">
    {payload?.map((entry: any) => (
      <div key={entry.value} className="flex items-center gap-1.5">
        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: entry.color }} />
        <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
          {entry.value}
        </span>
      </div>
    ))}
  </div>
);

export default function AISummaryCard({ summary, riskBreakdown, loading }: AISummaryCardProps) {
  const pieData = riskBreakdown
    ? RISK_COLORS.map(r => ({ name: r.label, value: (riskBreakdown as any)[r.key], fill: r.color })).filter(d => d.value > 0)
    : [];

  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b flex items-center gap-2" style={{ borderColor: "hsl(var(--slate-border))" }}>
        <Sparkles className="w-4 h-4" style={{ color: "hsl(var(--sand))" }} />
        <div>
          <p className="section-label mb-0.5">AI-Powered</p>
          <h2 className="font-display text-xl" style={{ color: "hsl(var(--foreground))" }}>
            Analyst Summary
          </h2>
        </div>
      </div>

      <div className="p-5">
        {loading ? (
          <div className="space-y-2 animate-pulse">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-3 rounded" style={{ background: "hsl(var(--slate-raised))", width: `${85 - i * 10}%` }} />
            ))}
          </div>
        ) : summary ? (
          <p className="text-sm leading-relaxed" style={{ color: "hsl(var(--foreground) / 0.85)", fontFamily: "Inter, sans-serif" }}>
            {summary}
          </p>
        ) : (
          <div className="flex items-center gap-3 py-4" style={{ color: "hsl(var(--muted-foreground))" }}>
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span className="font-mono text-xs">Run a scan to generate AI analyst summary</span>
          </div>
        )}

        {/* Pie chart */}
        {loading ? (
          <div className="mt-5 flex items-center justify-center">
            <Loader2 className="w-5 h-5 animate-spin" style={{ color: "hsl(var(--muted-foreground))" }} />
          </div>
        ) : pieData.length > 0 ? (
          <div className="mt-5 border-t pt-5" style={{ borderColor: "hsl(var(--slate-border))" }}>
            <p className="section-label mb-3">Risk Breakdown</p>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={72}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.fill} stroke="hsl(var(--glass-bg))" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend content={<CustomLegend />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : null}
      </div>
    </div>
  );
}
