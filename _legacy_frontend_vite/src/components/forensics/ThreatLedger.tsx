import { ShieldAlert, Loader2, AlertTriangle, ChevronRight } from "lucide-react";

export type ThreatEntry = {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  name: string;
  path: string;
  type: string;
  timestamp: string;
  hash: string;
};

interface ThreatLedgerProps {
  threats: ThreatEntry[];
  loading: boolean;
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
};

export default function ThreatLedger({ threats, loading }: ThreatLedgerProps) {
  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      {/* Header */}
      <div
        className="px-5 py-4 border-b flex items-center justify-between"
        style={{ borderColor: "hsl(var(--slate-border))" }}
      >
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4" style={{ color: "hsl(var(--threat-critical))" }} />
          <div>
            <p className="section-label mb-0.5">Active IOCs</p>
            <h2 className="font-display text-xl" style={{ color: "hsl(var(--foreground))" }}>
              Threat Ledger
            </h2>
          </div>
        </div>
        {!loading && threats.length > 0 && (
          <span
            className="font-mono text-xs px-2.5 py-1 rounded-full"
            style={{ background: "hsl(var(--threat-critical) / 0.12)", color: "hsl(var(--threat-critical))", border: "1px solid hsl(var(--threat-critical) / 0.25)" }}
          >
            {threats.length} active
          </span>
        )}
      </div>

      {/* Table header */}
      <div
        className="px-5 py-2.5 grid grid-cols-12 gap-3 border-b"
        style={{ background: "hsl(var(--slate-panel))", borderColor: "hsl(var(--slate-border))" }}
      >
        {["Severity", "Threat Name", "File Path", "Type", "Timestamp"].map((h, i) => (
          <span key={h} className={`section-label ${i === 0 ? "col-span-1" : i === 1 ? "col-span-3" : i === 2 ? "col-span-4" : i === 3 ? "col-span-2" : "col-span-2"}`}>
            {h}
          </span>
        ))}
      </div>

      {/* Rows */}
      <div className="divide-y max-h-80 overflow-y-auto" style={{ borderColor: "hsl(var(--slate-border))" }}>
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="px-5 py-3.5 grid grid-cols-12 gap-3 animate-pulse">
              <div className="col-span-1 h-5 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-3 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-4 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-2 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-2 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
            </div>
          ))
        ) : threats.length === 0 ? (
          <div className="px-5 py-10 flex flex-col items-center gap-3">
            <AlertTriangle className="w-8 h-8" style={{ color: "hsl(var(--muted-foreground))" }} />
            <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
              No threats detected — run a scan to populate the ledger
            </span>
          </div>
        ) : (
          threats.map((threat) => (
            <div
              key={threat.id}
              className="px-5 py-3.5 grid grid-cols-12 gap-3 items-center hover:bg-[hsl(var(--slate-raised)/0.5)] transition-colors cursor-pointer group"
            >
              {/* Severity */}
              <div className="col-span-1">
                <span className={`badge-${threat.severity} font-mono text-xs px-1.5 py-0.5 rounded font-bold`}>
                  {SEVERITY_LABELS[threat.severity]}
                </span>
              </div>
              {/* Name */}
              <div className="col-span-3">
                <span className="font-mono text-xs font-medium truncate block" style={{ color: "hsl(var(--foreground))" }}>
                  {threat.name}
                </span>
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {threat.hash}
                </span>
              </div>
              {/* Path */}
              <div className="col-span-4">
                <span className="font-mono text-xs truncate block" style={{ color: "hsl(var(--sand))" }}>
                  {threat.path}
                </span>
              </div>
              {/* Type */}
              <div className="col-span-2">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {threat.type}
                </span>
              </div>
              {/* Timestamp + arrow */}
              <div className="col-span-2 flex items-center justify-between">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {threat.timestamp}
                </span>
                <ChevronRight
                  className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
                  style={{ color: "hsl(var(--rust))" }}
                />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
