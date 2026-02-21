import { useState, useMemo } from "react";
import { Search, Filter, ChevronDown, Files, Loader2 } from "lucide-react";

export type FileEntry = {
  id: string;
  name: string;
  path: string;
  size: string;
  mime: string;
  risk: "critical" | "high" | "medium" | "low" | "clean";
  modified: string;
};

const RISK_OPTIONS = ["all", "critical", "high", "medium", "low", "clean"];
const MIME_OPTIONS = ["all", "application/exe", "application/pdf", "image/jpeg", "text/plain", "application/zip", "application/dll"];

const SEVERITY_LABELS: Record<string, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  clean: "OK",
};

interface FileInventoryProps {
  files: FileEntry[];
  loading: boolean;
}

export default function FileInventory({ files, loading }: FileInventoryProps) {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [mimeFilter, setMimeFilter] = useState("all");
  const [visibleCount, setVisibleCount] = useState(10);

  const filtered = useMemo(() => {
    return files.filter(f => {
      const matchSearch = f.name.toLowerCase().includes(search.toLowerCase()) ||
        f.path.toLowerCase().includes(search.toLowerCase());
      const matchRisk = riskFilter === "all" || f.risk === riskFilter;
      const matchMime = mimeFilter === "all" || f.mime === mimeFilter;
      return matchSearch && matchRisk && matchMime;
    });
  }, [files, search, riskFilter, mimeFilter]);

  const visible = filtered.slice(0, visibleCount);

  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      {/* Header */}
      <div
        className="px-5 py-4 border-b flex flex-wrap items-center gap-3"
        style={{ borderColor: "hsl(var(--slate-border))" }}
      >
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <Files className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--sand))" }} />
          <div>
            <p className="section-label mb-0.5">Evidence Artifacts</p>
            <h2 className="font-display text-xl" style={{ color: "hsl(var(--foreground))" }}>
              File Inventory
            </h2>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none" style={{ color: "hsl(var(--muted-foreground))" }} />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search files…"
              className="forensic-input rounded-md pl-8 pr-3 py-2 text-xs w-44"
            />
          </div>

          {/* Risk filter */}
          <div className="relative">
            <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{ color: "hsl(var(--muted-foreground))" }} />
            <select
              value={riskFilter}
              onChange={e => setRiskFilter(e.target.value)}
              className="forensic-select rounded-md pl-7 pr-7 py-2 text-xs appearance-none w-32"
            >
              {RISK_OPTIONS.map(o => (
                <option key={o} value={o}>{o === "all" ? "All Risks" : o.charAt(0).toUpperCase() + o.slice(1)}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{ color: "hsl(var(--muted-foreground))" }} />
          </div>

          {/* MIME filter */}
          <div className="relative">
            <select
              value={mimeFilter}
              onChange={e => setMimeFilter(e.target.value)}
              className="forensic-select rounded-md px-3 pr-7 py-2 text-xs appearance-none w-44"
            >
              {MIME_OPTIONS.map(o => (
                <option key={o} value={o}>{o === "all" ? "All MIME Types" : o}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{ color: "hsl(var(--muted-foreground))" }} />
          </div>
        </div>

        {!loading && (
          <span className="font-mono text-xs ml-auto" style={{ color: "hsl(var(--muted-foreground))" }}>
            {filtered.length} / {files.length} files
          </span>
        )}
      </div>

      {/* Column headers */}
      <div
        className="px-5 py-2.5 grid grid-cols-12 gap-3 border-b"
        style={{ background: "hsl(var(--slate-panel))", borderColor: "hsl(var(--slate-border))" }}
      >
        {[
          { label: "Risk", span: "col-span-1" },
          { label: "Filename", span: "col-span-3" },
          { label: "Path", span: "col-span-3" },
          { label: "MIME Type", span: "col-span-2" },
          { label: "Size", span: "col-span-1" },
          { label: "Modified", span: "col-span-2" },
        ].map(h => (
          <span key={h.label} className={`section-label ${h.span}`}>{h.label}</span>
        ))}
      </div>

      {/* File rows */}
      <div className="divide-y max-h-96 overflow-y-auto" style={{ borderColor: "hsl(var(--slate-border))" }}>
        {loading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="px-5 py-3 grid grid-cols-12 gap-3 animate-pulse">
              <div className="col-span-1 h-5 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-3 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-3 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-2 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-1 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
              <div className="col-span-2 h-3 rounded" style={{ background: "hsl(var(--slate-raised))" }} />
            </div>
          ))
        ) : visible.length === 0 ? (
          <div className="px-5 py-10 flex flex-col items-center gap-3">
            <Files className="w-8 h-8" style={{ color: "hsl(var(--muted-foreground))" }} />
            <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
              {files.length === 0 ? "No files indexed — run a scan first" : "No files match current filters"}
            </span>
          </div>
        ) : (
          visible.map(file => (
            <div
              key={file.id}
              className="px-5 py-3 grid grid-cols-12 gap-3 items-center hover:bg-[hsl(var(--slate-raised)/0.4)] transition-colors cursor-pointer"
            >
              <div className="col-span-1">
                <span className={`badge-${file.risk} font-mono text-xs px-1.5 py-0.5 rounded font-bold`}>
                  {SEVERITY_LABELS[file.risk]}
                </span>
              </div>
              <div className="col-span-3">
                <span className="font-mono text-xs truncate block" style={{ color: "hsl(var(--foreground))" }}>
                  {file.name}
                </span>
              </div>
              <div className="col-span-3">
                <span className="font-mono text-xs truncate block" style={{ color: "hsl(var(--sand))" }}>
                  {file.path}
                </span>
              </div>
              <div className="col-span-2">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {file.mime}
                </span>
              </div>
              <div className="col-span-1">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {file.size}
                </span>
              </div>
              <div className="col-span-2">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                  {file.modified}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Load more */}
      {!loading && visible.length < filtered.length && (
        <div className="px-5 py-3.5 border-t flex items-center justify-between" style={{ borderColor: "hsl(var(--slate-border))" }}>
          <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
            Showing {visible.length} of {filtered.length}
          </span>
          <button
            className="btn-ghost rounded-md px-4 py-2 flex items-center gap-2"
            onClick={() => setVisibleCount(c => c + 20)}
          >
            <Loader2 className="w-3 h-3" />
            Load More
          </button>
        </div>
      )}
    </div>
  );
}
