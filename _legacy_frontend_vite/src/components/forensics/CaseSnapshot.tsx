import { TrendingUp, Clock, Files, ShieldAlert, Loader2 } from "lucide-react";

interface SnapshotData {
  confidence: number;
  executionTime: string;
  totalFiles: number;
  threats: number;
}

interface CaseSnapshotProps {
  data: SnapshotData | null;
  loading: boolean;
}

const CARDS = [
  {
    key: "confidence",
    label: "Confidence Score",
    icon: TrendingUp,
    unit: "%",
    color: "hsl(var(--rust))",
    description: "ML classifier certainty",
  },
  {
    key: "executionTime",
    label: "Execution Time",
    icon: Clock,
    unit: "",
    color: "hsl(var(--sand))",
    description: "Full pipeline duration",
  },
  {
    key: "totalFiles",
    label: "Total Files",
    icon: Files,
    unit: "",
    color: "hsl(var(--foreground))",
    description: "Indexed file objects",
  },
  {
    key: "threats",
    label: "Threats Found",
    icon: ShieldAlert,
    unit: "",
    color: "hsl(var(--threat-critical))",
    description: "IOC & malware matches",
  },
];

export default function CaseSnapshot({ data, loading }: CaseSnapshotProps) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {CARDS.map((card) => {
        const Icon = card.icon;
        const value = data ? (data as any)[card.key] : null;

        return (
          <div
            key={card.key}
            className="glass-panel rust-glow-hover rounded-xl p-4 relative overflow-hidden"
          >
            {/* Top stripe */}
            <div
              className="absolute top-0 left-0 right-0 h-0.5 rounded-t-xl"
              style={{ background: `linear-gradient(90deg, ${card.color}, transparent)` }}
            />

            <div className="flex items-start justify-between mb-3">
              <span className="section-label">{card.label}</span>
              <div
                className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
                style={{ background: `${card.color}18`, border: `1px solid ${card.color}30` }}
              >
                <Icon className="w-3.5 h-3.5" style={{ color: card.color }} />
              </div>
            </div>

            {loading ? (
              <div className="flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" style={{ color: "hsl(var(--muted-foreground))" }} />
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  Processing…
                </span>
              </div>
            ) : value !== null ? (
              <>
                <div className="metric-value" style={{ color: card.color }}>
                  {typeof value === "number" && card.key === "totalFiles"
                    ? value.toLocaleString()
                    : value}
                  {card.unit}
                </div>
                <p className="font-mono text-xs mt-1.5" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {card.description}
                </p>
              </>
            ) : (
              <>
                <div className="metric-value" style={{ color: "hsl(var(--slate-border))" }}>
                  —
                </div>
                <p className="font-mono text-xs mt-1.5" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {card.description}
                </p>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
