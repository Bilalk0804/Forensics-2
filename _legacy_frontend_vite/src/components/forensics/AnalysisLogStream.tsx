import { useEffect, useRef, useState } from "react";
import { Terminal, Pause, Play, Trash2 } from "lucide-react";

export type LogEntry = {
  id: string;
  ts: string;
  level: "info" | "warn" | "error" | "debug";
  msg: string;
};

const LEVEL_COLORS: Record<string, string> = {
  info: "hsl(var(--status-complete))",
  warn: "hsl(var(--threat-medium))",
  error: "hsl(var(--threat-critical))",
  debug: "hsl(var(--muted-foreground))",
};

const LEVEL_LABELS: Record<string, string> = {
  info: "INFO ",
  warn: "WARN ",
  error: "ERROR",
  debug: "DEBUG",
};

interface AnalysisLogStreamProps {
  logs: LogEntry[];
  live: boolean;
}

export default function AnalysisLogStream({ logs, live }: AnalysisLogStreamProps) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);
  const [cleared, setCleared] = useState(false);
  const [displayLogs, setDisplayLogs] = useState<LogEntry[]>([]);

  useEffect(() => {
    if (!cleared) {
      setDisplayLogs(logs);
    }
  }, [logs, cleared]);

  useEffect(() => {
    if (!paused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [displayLogs, paused]);

  const handleClear = () => {
    setCleared(true);
    setDisplayLogs([]);
  };

  const handleTogglePause = () => {
    if (paused) {
      setCleared(false);
      setPaused(false);
    } else {
      setPaused(true);
    }
  };

  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      {/* Header */}
      <div
        className="px-5 py-3.5 border-b flex items-center justify-between"
        style={{ borderColor: "hsl(var(--slate-border))" }}
      >
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4" style={{ color: "hsl(var(--rust))" }} />
          <span className="font-display text-lg" style={{ color: "hsl(var(--foreground))" }}>
            Analysis Log Stream
          </span>
          {live && !paused && (
            <span
              className="flex items-center gap-1.5 font-mono text-xs px-2 py-0.5 rounded-full"
              style={{
                background: "hsl(var(--status-complete) / 0.12)",
                color: "hsl(var(--status-complete))",
                border: "1px solid hsl(var(--status-complete) / 0.25)"
              }}
            >
              <span className="w-1.5 h-1.5 rounded-full pulse-dot" style={{ background: "hsl(var(--status-complete))" }} />
              LIVE
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleTogglePause}
            className="btn-ghost rounded-md px-3 py-1.5 flex items-center gap-1.5"
          >
            {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            <span className="text-xs">{paused ? "Resume" : "Pause"}</span>
          </button>
          <button
            onClick={handleClear}
            className="btn-ghost rounded-md px-3 py-1.5 flex items-center gap-1.5"
          >
            <Trash2 className="w-3 h-3" />
            <span className="text-xs">Clear</span>
          </button>
        </div>
      </div>

      {/* Log area */}
      <div
        className="font-mono text-xs overflow-y-auto relative"
        style={{
          height: 260,
          background: "hsl(222 25% 5%)",
          scrollbarWidth: "thin",
          scrollbarColor: "hsl(var(--slate-border)) transparent",
        }}
      >
        {displayLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3">
            <Terminal className="w-8 h-8" style={{ color: "hsl(var(--muted-foreground))" }} />
            <span style={{ color: "hsl(var(--muted-foreground))" }}>
              {live ? "Awaiting log output…" : "No logs — start a scan to see output"}
            </span>
          </div>
        ) : (
          <div className="p-4 space-y-0.5">
            {displayLogs.map((log, i) => (
              <div
                key={log.id}
                className={`log-entry log-${log.level} pl-3 py-0.5 log-animate`}
                style={{ animationDelay: `${Math.min(i * 20, 200)}ms` }}
              >
                <span style={{ color: "hsl(var(--muted-foreground))" }}>{log.ts} </span>
                <span style={{ color: LEVEL_COLORS[log.level], fontWeight: 600 }}>
                  [{LEVEL_LABELS[log.level]}]
                </span>
                {" "}
                <span style={{ color: log.level === "error" ? "hsl(var(--threat-critical))" : log.level === "warn" ? "hsl(var(--threat-medium))" : "hsl(var(--foreground) / 0.8)" }}>
                  {log.msg}
                </span>
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        )}
      </div>
    </div>
  );
}
