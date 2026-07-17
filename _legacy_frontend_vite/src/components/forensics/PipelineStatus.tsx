import { CheckCircle2, Loader2, Clock, XCircle, BarChart3 } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

export type PipelineStage = {
  name: string;
  status: "complete" | "running" | "queued" | "error";
  duration?: string;
  findings?: number;
};

const STATUS_ICONS = {
  complete: <CheckCircle2 className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--status-complete))" }} />,
  running: <Loader2 className="w-4 h-4 flex-shrink-0 animate-spin" style={{ color: "hsl(var(--status-running))" }} />,
  queued: <Clock className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--status-queued))" }} />,
  error: <XCircle className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--status-error))" }} />,
};

const STATUS_COLORS = {
  complete: "hsl(var(--status-complete))",
  running: "hsl(var(--status-running))",
  queued: "hsl(var(--status-queued))",
  error: "hsl(var(--status-error))",
};

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload?.length) {
    return (
      <div className="glass-panel rounded-lg p-3 border" style={{ borderColor: "hsl(var(--rust) / 0.3)" }}>
        <p className="font-mono text-xs mb-1" style={{ color: "hsl(var(--muted-foreground))" }}>{label}</p>
        <p className="font-display text-lg" style={{ color: "hsl(var(--rust))" }}>
          {payload[0].value} findings
        </p>
      </div>
    );
  }
  return null;
};

interface PipelineStatusProps {
  stages: PipelineStage[];
  loading: boolean;
}

export default function PipelineStatus({ stages, loading }: PipelineStatusProps) {
  const chartData = stages
    .filter(s => s.findings !== undefined)
    .map(s => ({ name: s.name.replace(" Analysis", "").replace(" Scanner", ""), findings: s.findings }));

  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b flex items-center justify-between" style={{ borderColor: "hsl(var(--slate-border))" }}>
        <div>
          <p className="section-label mb-1">Pipeline Status</p>
          <h2 className="font-display text-xl" style={{ color: "hsl(var(--foreground))" }}>
            Analysis Stages
          </h2>
        </div>
        <BarChart3 className="w-4 h-4" style={{ color: "hsl(var(--rust))" }} />
      </div>

      {/* Stage list */}
      <div className="divide-y" style={{ borderColor: "hsl(var(--slate-border))" }}>
        {loading
          ? Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="px-5 py-3 flex items-center gap-3 animate-pulse">
                <div className="w-4 h-4 rounded-full" style={{ background: "hsl(var(--slate-raised))" }} />
                <div className="flex-1 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
                <div className="w-12 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              </div>
            ))
          : stages.map((stage) => (
              <div
                key={stage.name}
                className="px-5 py-3 flex items-center gap-3 transition-colors"
                style={{ background: stage.status === "running" ? "hsl(var(--rust) / 0.04)" : undefined }}
              >
                {STATUS_ICONS[stage.status]}
                <span className="flex-1 font-mono text-xs" style={{ color: "hsl(var(--foreground))" }}>
                  {stage.name}
                </span>
                {stage.findings !== undefined && (
                  <span
                    className="font-mono text-xs px-2 py-0.5 rounded"
                    style={{
                      background: "hsl(var(--rust) / 0.12)",
                      color: "hsl(var(--rust))",
                    }}
                  >
                    {stage.findings}
                  </span>
                )}
                {stage.duration && (
                  <span className="font-mono text-xs ml-2" style={{ color: "hsl(var(--muted-foreground))" }}>
                    {stage.duration}
                  </span>
                )}
                <span
                  className={`text-xs font-mono capitalize`}
                  style={{ color: STATUS_COLORS[stage.status], minWidth: 60, textAlign: "right" }}
                >
                  {stage.status}
                </span>
              </div>
            ))}
      </div>

      {/* Bar chart */}
      {chartData.length > 0 && (
        <div className="px-5 pt-5 pb-4 border-t" style={{ borderColor: "hsl(var(--slate-border))" }}>
          <p className="section-label mb-3">Findings by Stage</p>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={chartData} barSize={24} margin={{ left: -24, right: 0 }}>
              <XAxis
                dataKey="name"
                tick={{ fill: "hsl(218, 12%, 45%)", fontSize: 10, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "hsl(218, 12%, 45%)", fontSize: 10, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "hsl(218 20% 14% / 0.8)" }} />
              <Bar dataKey="findings" radius={[3, 3, 0, 0]}>
                {chartData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={index % 2 === 0 ? "hsl(var(--rust))" : "hsl(var(--rust-dim))"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
