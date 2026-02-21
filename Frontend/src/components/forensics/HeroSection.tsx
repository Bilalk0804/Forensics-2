import { useState } from "react";
import { Download, ScanLine, ChevronDown, Loader2, ShieldAlert, CheckCircle2, AlertCircle } from "lucide-react";
import heroImg from "@/assets/forensics-hero.jpg";

type ScanStatus = "idle" | "scanning" | "complete" | "error";

const DRIVES = ["/dev/sda", "/dev/sdb", "/dev/nvme0n1", "\\\\.\\ PhysicalDrive0", "\\\\.\\PhysicalDrive1", "E:\\Evidence\\img001.dd"];
const REPORTS = ["RPT-2024-0091", "RPT-2024-0088", "RPT-2024-0075", "RPT-2023-0142"];

interface HeroSectionProps {
  onScan: (drive: string) => void;
  scanStatus: ScanStatus;
}

const STATUS_CONFIG: Record<ScanStatus, { label: string; color: string; icon: React.ReactNode }> = {
  idle: { label: "Awaiting Input", color: "badge-clean", icon: <span className="w-2 h-2 rounded-full bg-current" /> },
  scanning: { label: "Scanning…", color: "badge-medium", icon: <Loader2 className="w-3 h-3 animate-spin" /> },
  complete: { label: "Analysis Complete", color: "badge-low", icon: <CheckCircle2 className="w-3 h-3" /> },
  error: { label: "Error — Retry", color: "badge-critical", icon: <AlertCircle className="w-3 h-3" /> },
};

export default function HeroSection({ onScan, scanStatus }: HeroSectionProps) {
  const [drive, setDrive] = useState("");
  const [report, setReport] = useState(REPORTS[0]);

  const status = STATUS_CONFIG[scanStatus];

  return (
    <div className="relative overflow-hidden rounded-xl glass-panel scan-lines">
      {/* Background image */}
      <div
        className="absolute inset-0 bg-cover bg-center opacity-20"
        style={{ backgroundImage: `url(${heroImg})` }}
      />
      {/* Gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-r from-background via-background/80 to-transparent" />

      <div className="relative z-10 px-6 py-8 md:px-10 md:py-10">
        {/* Badge */}
        <div className="flex items-center gap-2 mb-5">
          <ShieldAlert className="w-4 h-4 text-primary" />
          <span className="section-label" style={{ color: "hsl(var(--rust))" }}>
            Sentinel Forensics · v3.7.2
          </span>
        </div>

        {/* Headline */}
        <h1 className="font-display text-5xl md:text-6xl lg:text-7xl mb-2 leading-none tracking-tight"
          style={{ color: "hsl(var(--foreground))" }}>
          Evidence Analysis
          <br />
          <span style={{ color: "hsl(var(--rust))" }}>Console</span>
        </h1>
        <p className="font-mono text-xs mb-8" style={{ color: "hsl(var(--muted-foreground))" }}>
          Digital forensics · chain-of-custody preserved · NIST SP 800-86 compliant
        </p>

        {/* Controls row */}
        <div className="flex flex-wrap gap-3 items-end">
          {/* Drive selector */}
          <div className="flex flex-col gap-1.5 flex-1 min-w-[200px]">
            <label className="section-label">Target Drive / Image</label>
            <input
              list="drive-list"
              value={drive}
              onChange={e => setDrive(e.target.value)}
              placeholder="/dev/sda or E:\image.dd"
              className="forensic-input rounded-md px-3 py-2.5 w-full"
            />
            <datalist id="drive-list">
              {DRIVES.map(d => <option key={d} value={d} />)}
            </datalist>
          </div>

          {/* Scan button */}
          <button
            className="btn-scan rounded-md px-6 py-2.5 flex items-center gap-2 flex-shrink-0"
            disabled={!drive || scanStatus === "scanning"}
            onClick={() => drive && onScan(drive)}
          >
            {scanStatus === "scanning"
              ? <Loader2 className="w-4 h-4 animate-spin" />
              : <ScanLine className="w-4 h-4" />}
            {scanStatus === "scanning" ? "Scanning…" : "Scan Drive"}
          </button>

          {/* Report selector */}
          <div className="flex flex-col gap-1.5 min-w-[170px]">
            <label className="section-label">Report</label>
            <div className="relative">
              <select
                value={report}
                onChange={e => setReport(e.target.value)}
                className="forensic-select rounded-md px-3 py-2.5 w-full appearance-none pr-8"
              >
                {REPORTS.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
                style={{ color: "hsl(var(--muted-foreground))" }} />
            </div>
          </div>

          {/* PDF Download */}
          <button className="btn-ghost rounded-md px-4 py-2.5 flex items-center gap-2 flex-shrink-0">
            <Download className="w-3.5 h-3.5" />
            PDF Report
          </button>

          {/* Status pill */}
          <div className={`flex items-center gap-1.5 px-3 py-2 rounded-full text-xs font-mono flex-shrink-0 ${status.color}`}>
            {status.icon}
            {status.label}
          </div>
        </div>
      </div>
    </div>
  );
}
