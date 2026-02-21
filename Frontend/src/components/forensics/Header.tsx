import { Settings, Cpu, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";

type Status = "idle" | "scanning" | "complete" | "error";

const STATUS_CONFIG: Record<Status, { label: string; dotColor: string; bgColor: string }> = {
  idle: { label: "Idle", dotColor: "hsl(var(--muted-foreground))", bgColor: "hsl(var(--muted) / 0.5)" },
  scanning: { label: "Scanning", dotColor: "hsl(var(--rust))", bgColor: "hsl(var(--rust) / 0.1)" },
  complete: { label: "Completed", dotColor: "hsl(var(--status-complete))", bgColor: "hsl(var(--status-complete) / 0.1)" },
  error: { label: "Error", dotColor: "hsl(var(--destructive))", bgColor: "hsl(var(--destructive) / 0.1)" },
};

interface HeaderProps {
  status: Status;
}

export default function Header({ status }: HeaderProps) {
  const s = STATUS_CONFIG[status];

  return (
    <motion.header
      initial={{ opacity: 0, y: -12 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center justify-between px-6 py-4"
    >
      {/* Left — Branding */}
      <div className="flex items-center gap-6">
        <Link to="/" className="flex items-center gap-3 no-underline">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center"
            style={{ background: "hsl(var(--rust) / 0.15)", border: "1px solid hsl(var(--rust) / 0.25)" }}
          >
            <ShieldCheck className="w-5 h-5" style={{ color: "hsl(var(--rust))" }} />
          </div>
          <div>
            <h1 className="font-display text-lg leading-tight" style={{ color: "hsl(var(--foreground))" }}>
              Sentinel Forensics
            </h1>
            <p className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
              AI-Powered Evidence Analysis
            </p>
          </div>
        </Link>
      </div>

      {/* Right — Status + GPU + Settings */}
      <div className="flex items-center gap-3">
        {/* Status badge */}
        <div
          className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium"
          style={{ background: s.bgColor, color: s.dotColor, border: `1px solid ${s.dotColor}30` }}
        >
          <span
            className={`w-2 h-2 rounded-full ${status === "scanning" ? "pulse-dot" : ""}`}
            style={{ background: s.dotColor }}
          />
          {s.label}
        </div>

        {/* GPU indicator */}
        <div
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs"
          style={{
            background: "hsl(var(--muted) / 0.5)",
            color: "hsl(var(--muted-foreground))",
            border: "1px solid hsl(var(--border))",
          }}
        >
          <Cpu className="w-3.5 h-3.5" />
          GPU Ready
        </div>

        {/* Settings */}
        <button
          className="w-9 h-9 rounded-lg flex items-center justify-center transition-colors"
          style={{
            background: "hsl(var(--muted) / 0.5)",
            border: "1px solid hsl(var(--border))",
            color: "hsl(var(--muted-foreground))",
          }}
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </motion.header>
  );
}
