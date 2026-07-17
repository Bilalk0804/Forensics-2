import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Play, ArrowLeft, ArrowRight, TrendingUp, Clock, Files, ShieldAlert,
  Activity, Loader2, Download, RotateCcw, AlertTriangle, CheckCircle2,
  HardDrive, Eye, FileText, Bug, FileSearch, Headphones, Drama, Microscope
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import Header from "@/components/forensics/Header";
import DrivePicker from "@/components/forensics/DrivePicker";
import ModelSelection from "@/components/forensics/ModelSelection";
import AnalysisPresets from "@/components/forensics/AnalysisPresets";
import StatCard from "@/components/forensics/StatCard";
import ThreatLedger, { type ThreatEntry } from "@/components/forensics/ThreatLedger";
import FileInventory, { type FileEntry } from "@/components/forensics/FileInventory";
import AISummaryCard from "@/components/forensics/AISummaryCard";
import AnalysisLogStream, { type LogEntry } from "@/components/forensics/AnalysisLogStream";
import PipelineStatus, { type PipelineStage } from "@/components/forensics/PipelineStatus";
import { PRESETS, type PresetKey } from "@/hooks/useForensicsApi";
import { fetchDrives, fetchModels, type ModelOption } from "@/lib/api";
import { masterAgentAPI, type JobStatus } from "@/lib/masterAgentAPI";

const STEP_NAMES = ["Evidence Source", "AI Models", "Launch"] as const;

const MODEL_ICON_MAP: Record<string, LucideIcon> = {
  vision: Eye, text: FileText, malware: Bug, file: FileSearch, audio: Headphones, deepfake: Drama,
};

// ─── Helpers ─────────────────────────────────────────────────

function tsNow(): string {
  const now = new Date();
  return `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
}

function makeLog(level: LogEntry["level"], msg: string): LogEntry {
  return { id: `log-${Date.now()}-${Math.random()}`, ts: tsNow(), level, msg };
}

/** Convert backend job results into dashboard-friendly data */
function mapJobResults(job: JobStatus) {
  const threats: ThreatEntry[] = [];
  const files: FileEntry[] = [];
  let totalFiles = 0;
  let totalThreats = 0;
  let confidenceSum = 0;
  let confidenceCount = 0;

  if (job.results) {
    Object.entries(job.results).forEach(([modelId, result]) => {
      const details = result.details || [];
      totalFiles += result.files_analyzed || 0;
      totalThreats += result.threats || 0;

      details.forEach((d, idx) => {
        if (!d.result || d.result.status === "skipped") return;

        const r = d.result as Record<string, unknown>;
        const fileName = d.file.split(/[\\/]/).pop() || d.file;
        const filePath = d.file.substring(0, d.file.lastIndexOf("\\") + 1) || d.file;

        // Track real confidence from model output
        if (typeof r.confidence === "number") {
          confidenceSum += r.confidence as number;
          confidenceCount++;
        }

        // Determine per-file risk from actual model output
        const isThreat =
          r.is_malicious === true ||
          r.is_deepfake === true ||
          r.violence_detected === true ||
          (typeof r.risk_level === "string" && ["HIGH", "CRITICAL"].includes((r.risk_level as string).toUpperCase()));

        const riskLevel: FileEntry["risk"] = d.error
          ? "high"
          : isThreat
            ? "high"
            : (r.risk_level as string)?.toUpperCase() === "MEDIUM"
              ? "medium"
              : "clean";

        // Only include files with actual threats (MEDIUM/HIGH/CRITICAL)
        if (riskLevel !== "clean") {
          files.push({
            id: `${modelId}-f${idx}`,
            name: fileName,
            path: filePath,
            size: r.size_bytes != null ? `${(r.size_bytes as number).toLocaleString()} B` : "",
            mime: (r.mime_type as string) || "",
            risk: riskLevel,
            modified: "",
          });
        }

        // Add to threat ledger if real threat detected
        if (isThreat) {
          const severity: ThreatEntry["severity"] =
            (r.risk_level as string)?.toUpperCase() === "CRITICAL" ? "critical"
            : r.is_malicious ? "high"
            : r.is_deepfake ? "high"
            : r.violence_detected ? "high"
            : "medium";

          threats.push({
            id: `${modelId}-t${idx}`,
            severity,
            name:
              (r.threat_label as string) ||
              (r.label as string) ||
              (r.is_deepfake ? "Deepfake detected" : "") ||
              (r.violence_detected ? "Violence detected" : "") ||
              `${modelId} threat`,
            path: d.file,
            type: modelId,
            timestamp: new Date().toTimeString().slice(0, 8),
            hash: (r.hashes as any)?.sha256 || "",
          });
        }
      });
    });
  }

  const avgConfidence = confidenceCount > 0
    ? Math.round((confidenceSum / confidenceCount) * 100)
    : null;

  return { threats, files, totalFiles, totalThreats, avgConfidence };
}

// ─── Page Component ──────────────────────────────────────────

type ScanStatus = "idle" | "scanning" | "complete" | "error";
type WorkflowStep = 1 | 2 | 3;

export default function Index() {
  // Workflow state
  const [step, setStep] = useState<WorkflowStep>(1);
  const [selectedDrive, setSelectedDrive] = useState<string | null>(null);
  const [selectedModels, setSelectedModels] = useState<Set<string>>(
    new Set(["vision", "text", "malware", "file"])
  );
  const [activePreset, setActivePreset] = useState<PresetKey>("balanced");

  // Backend data
  const [drives, setDrives] = useState<{ letter: string; label: string }[]>([]);
  const [drivesLoading, setDrivesLoading] = useState(true);
  const [models, setModels] = useState<Record<string, ModelOption>>({});
  const [modelsLoading, setModelsLoading] = useState(true);

  // Scan state
  const [scanStatus, setScanStatus] = useState<ScanStatus>("idle");
  const [scanProgress, setScanProgress] = useState(0);
  const [showDashboard, setShowDashboard] = useState(false);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stages, setStages] = useState<PipelineStage[]>([]);
  const [threats, setThreats] = useState<ThreatEntry[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [snapshotData, setSnapshotData] = useState<{
    confidence: number; executionTime: string; totalFiles: number; threats: number;
  } | null>(null);
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [riskBreakdown, setRiskBreakdown] = useState<{
    critical: number; high: number; medium: number; low: number; clean: number;
  } | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);

  const logIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortRef = useRef(false);

  // ─── Fetch drives + models on mount ──────────────────────
  useEffect(() => {
    fetchDrives()
      .then((res) => {
        const driveList = res.drives.map((d) => ({
          letter: d,
          label: d.replace(/[:\\\/]+$/, "") + " Drive",
        }));
        setDrives(driveList);
        if (driveList.length > 0 && !selectedDrive) {
          setSelectedDrive(driveList[0].letter);
        }
      })
      .catch((err) => console.error("Failed to fetch drives:", err))
      .finally(() => setDrivesLoading(false));

    fetchModels()
      .then((res) => setModels(res.models))
      .catch((err) => console.error("Failed to fetch models:", err))
      .finally(() => setModelsLoading(false));
  }, []);

  const addLog = useCallback((log: LogEntry) => {
    setLogs(prev => [...prev.slice(-200), log]);
  }, []);

  // Handle preset selection
  const handlePresetSelect = useCallback((key: PresetKey) => {
    setActivePreset(key);
    if (key !== "custom") {
      const preset = PRESETS.find(p => p.key === key);
      if (preset) setSelectedModels(new Set(preset.modelIds));
    }
  }, []);

  const toggleModel = useCallback((id: string) => {
    setSelectedModels(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
    setActivePreset("custom");
  }, []);

  // ─── Start real scan via backend ─────────────────────────
  const startScan = useCallback(async () => {
    if (!selectedDrive) return;

    setScanStatus("scanning");
    setLoading(true);
    setShowDashboard(true);
    setScanProgress(0);
    setSnapshotData(null);
    setThreats([]);
    setFiles([]);
    setAiSummary(null);
    setRiskBreakdown(null);
    setScanError(null);
    abortRef.current = false;

    // Build pipeline stages from selected models
    const modelNames = Array.from(selectedModels);
    const runningStages: PipelineStage[] = modelNames.map((id, idx) => ({
      name: models[id]?.name || id,
      status: idx === 0 ? "running" : "queued",
    }));
    setStages(runningStages);

    addLog(makeLog("info", `Starting analysis on ${selectedDrive} with ${modelNames.length} model(s)…`));

    // Log real events — no fake log generation

    try {
      // 1. Start the analysis job
      const result = await masterAgentAPI.startAnalysis({
        evidencePath: selectedDrive,
        selectedModels: modelNames,
      });

      setCurrentJobId(result.jobId);
      addLog(makeLog("info", `Job ${result.jobId} started — polling for results…`));

      // 2. Poll for completion with progress callback
      const completedJob = await masterAgentAPI.waitForCompletion(
        result.jobId,
        (job: JobStatus) => {
          if (abortRef.current) return;

          // Update progress
          setScanProgress(job.progress ?? 0);

          // Update pipeline stages based on job results
          if (job.results) {
            const updatedStages: PipelineStage[] = modelNames.map((id) => {
              const modelResult = job.results?.[id];
              if (!modelResult) return { name: models[id]?.name || id, status: "queued" as const };
              if (modelResult.status === "completed" || modelResult.status === "success") {
                return {
                  name: models[id]?.name || id,
                  status: "complete" as const,
                  findings: modelResult.threats || 0,
                };
              }
              if (modelResult.status === "failed" || modelResult.status === "error") {
                return { name: models[id]?.name || id, status: "complete" as const };
              }
              return { name: models[id]?.name || id, status: "running" as const };
            });
            setStages(updatedStages);
          }
        },
        30 * 60 * 1000, // 30 min timeout
        5000,            // 5s poll
      );

      // 3. Process completed results
      if (logIntervalRef.current) clearInterval(logIntervalRef.current);

      if (completedJob.status === "completed") {
        const mapped = mapJobResults(completedJob);
        // Use job-level execution_time (startTime→endTime on backend), then fall back
        const rawSecs = completedJob.execution_time
          ?? ((completedJob.startTime && completedJob.endTime)
            ? (new Date(completedJob.endTime).getTime() - new Date(completedJob.startTime).getTime()) / 1000
            : null);
        const elapsed = rawSecs != null ? `${Number(rawSecs).toFixed(1)}s` : "—";

        setScanStatus("complete");
        setScanProgress(100);
        setThreats(mapped.threats);
        setFiles(mapped.files);
        setSnapshotData({
          confidence: mapped.avgConfidence ?? 0,
          executionTime: elapsed,
          totalFiles: mapped.totalFiles || mapped.files.length,
          threats: mapped.totalThreats || mapped.threats.length,
        });
        setStages(prev => prev.map(s => ({ ...s, status: "complete" as const })));

        // Build risk breakdown from real per-file results
        const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
        mapped.files.forEach(f => {
          if (f.risk === "high") riskCounts.high++;
          else if (f.risk === "medium") riskCounts.medium++;
          else riskCounts.clean++;
        });
        mapped.threats.forEach(t => {
          if (t.severity === "critical") riskCounts.critical++;
        });
        setRiskBreakdown(riskCounts);

        // Build summary from real results
        const fileCount = mapped.totalFiles || mapped.files.length;
        const threatCount = mapped.totalThreats || mapped.threats.length;
        const summaryParts = [
          `Analyzed ${fileCount} files across ${modelNames.length} model(s).`,
          `${threatCount} threat(s) detected.`,
        ];
        if (mapped.threats.length > 0) {
          summaryParts.push(
            `Flagged: ${mapped.threats.slice(0, 5).map(t => `${t.name} (${t.severity})`).join(", ")}.`
          );
        }
        if (mapped.avgConfidence != null) {
          summaryParts.push(`Average model confidence: ${mapped.avgConfidence}%.`);
        }
        setAiSummary(summaryParts.join(" "));

        addLog(makeLog("info", `Pipeline complete — ${fileCount} files, ${threatCount} threat(s)`));
      } else {
        // Job failed
        setScanStatus("error");
        setScanError(completedJob.error || "Analysis failed");
        addLog(makeLog("error", `Analysis failed: ${completedJob.error || "Unknown error"}`));
      }
    } catch (err: unknown) {
      if (logIntervalRef.current) clearInterval(logIntervalRef.current);
      const msg = err instanceof Error ? err.message : String(err);
      setScanStatus("error");
      setScanError(msg);
      addLog(makeLog("error", `Error: ${msg}`));
    } finally {
      setLoading(false);
    }
  }, [selectedDrive, selectedModels, models, addLog]);

  useEffect(() => {
    return () => {
      abortRef.current = true;
      if (logIntervalRef.current) clearInterval(logIntervalRef.current);
    };
  }, []);

  const canProceed = step === 1 ? !!selectedDrive : step === 2 ? selectedModels.size > 0 : true;

  // ─── Render ────────────────────────────────────────────────

  return (
    <div className="min-h-screen" style={{ background: "hsl(var(--background))" }}>
      <Header status={scanStatus} />

      <div className="max-w-[1400px] mx-auto px-4 md:px-8 pb-8">
        <AnimatePresence mode="wait">
          {!showDashboard ? (
            /* ═══ WORKFLOW PANEL ═══ */
            <motion.div
              key="workflow"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.96 }}
              transition={{ duration: 0.35 }}
              className="max-w-3xl mx-auto mt-8"
            >
              {/* Step indicator */}
              <div className="flex items-center justify-center gap-0 mb-8">
                {[1, 2, 3].map((s) => (
                  <div key={s} className="flex items-center gap-0">
                    <div className="flex flex-col items-center gap-1.5">
                      <motion.div
                        animate={{
                          scale: s === step ? 1.1 : 1,
                          boxShadow: s === step ? "0 0 16px -4px hsl(var(--rust) / 0.5)" : "none",
                        }}
                        className="w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold transition-all"
                        style={{
                          background: s <= step ? "hsl(var(--rust))" : "hsl(var(--muted))",
                          color: s <= step ? "hsl(var(--primary-foreground))" : "hsl(var(--muted-foreground))",
                          border: `1.5px solid ${s <= step ? "hsl(var(--rust))" : "hsl(var(--border))"}`,
                        }}
                      >
                        {s <= step && s < step ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          s
                        )}
                      </motion.div>
                      <span
                        className="text-[10px] font-medium whitespace-nowrap"
                        style={{ color: s <= step ? "hsl(var(--rust))" : "hsl(var(--muted-foreground))" }}
                      >
                        {STEP_NAMES[s - 1]}
                      </span>
                    </div>
                    {s < 3 && (
                      <div
                        className="w-16 md:w-24 h-0.5 rounded-full mx-3 mt-[-14px]"
                        style={{
                          background: s < step
                            ? "linear-gradient(90deg, hsl(var(--rust)), hsl(var(--rust) / 0.5))"
                            : "hsl(var(--border))",
                        }}
                      />
                    )}
                  </div>
                ))}
              </div>

              {/* Main workflow card */}
              <div className="glass-panel rounded-2xl p-6 md:p-8">
                <AnimatePresence mode="wait">
                  {step === 1 && (
                    <DrivePicker
                      key="step1"
                      drives={drives}
                      selectedDrive={selectedDrive}
                      onSelect={setSelectedDrive}
                      loading={drivesLoading}
                    />
                  )}
                  {step === 2 && (
                    <div key="step2">
                      <AnalysisPresets active={activePreset} onSelect={handlePresetSelect} />
                      <div className="mt-6 border-t pt-6" style={{ borderColor: "hsl(var(--border))" }}>
                        <ModelSelection
                          models={models}
                          selectedModels={selectedModels}
                          onToggle={toggleModel}
                          loading={modelsLoading}
                        />
                      </div>
                    </div>
                  )}
                  {step === 3 && (
                    <motion.div
                      key="step3"
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -12 }}
                    >
                      <h2 className="font-display text-xl mb-1" style={{ color: "hsl(var(--foreground))" }}>
                        Review & Launch
                      </h2>
                      <p className="text-sm mb-5" style={{ color: "hsl(var(--muted-foreground))" }}>
                        Confirm your selections before starting the forensic analysis
                      </p>

                      {/* Review summary cards */}
                      <div className="space-y-3 mb-6">
                        {/* Drive */}
                        <div
                          className="rounded-xl px-4 py-3 flex items-center gap-3"
                          style={{ background: "hsl(var(--slate-panel))", border: "1px solid hsl(var(--border))" }}
                        >
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "hsl(var(--rust) / 0.12)" }}>
                            <HardDrive className="w-4 h-4" style={{ color: "hsl(var(--rust))" }} />
                          </div>
                          <div className="flex-1">
                            <span className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "hsl(var(--muted-foreground))" }}>Evidence Source</span>
                            <p className="text-sm font-semibold" style={{ color: "hsl(var(--foreground))" }}>{selectedDrive || "—"}</p>
                          </div>
                        </div>

                        {/* Preset */}
                        <div
                          className="rounded-xl px-4 py-3 flex items-center gap-3"
                          style={{ background: "hsl(var(--slate-panel))", border: "1px solid hsl(var(--border))" }}
                        >
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "hsl(var(--rust) / 0.12)" }}>
                            <Activity className="w-4 h-4" style={{ color: "hsl(var(--rust))" }} />
                          </div>
                          <div className="flex-1">
                            <span className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "hsl(var(--muted-foreground))" }}>Analysis Preset</span>
                            <p className="text-sm font-semibold capitalize" style={{ color: "hsl(var(--foreground))" }}>{activePreset}</p>
                          </div>
                        </div>

                        {/* Selected models */}
                        <div
                          className="rounded-xl px-4 py-3"
                          style={{ background: "hsl(var(--slate-panel))", border: "1px solid hsl(var(--border))" }}
                        >
                          <span className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "hsl(var(--muted-foreground))" }}>
                            AI Models ({selectedModels.size})
                          </span>
                          <div className="flex flex-wrap gap-2 mt-2">
                            {Array.from(selectedModels).map((id) => {
                              const Ic = MODEL_ICON_MAP[id] || Microscope;
                              return (
                                <span
                                  key={id}
                                  className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-lg"
                                  style={{ background: "hsl(var(--rust) / 0.10)", color: "hsl(var(--rust))", border: "1px solid hsl(var(--rust) / 0.2)" }}
                                >
                                  <Ic className="w-3.5 h-3.5" />
                                  {models[id]?.name || id}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      </div>

                      {/* Launch button */}
                      <div className="text-center">
                        <motion.button
                          whileHover={{ scale: 1.03 }}
                          whileTap={{ scale: 0.97 }}
                          onClick={startScan}
                          className="inline-flex items-center gap-3 px-10 py-4 rounded-xl font-display text-lg font-bold transition-all"
                          style={{
                            background: "linear-gradient(135deg, hsl(var(--rust)), hsl(var(--rust-glow)))",
                            color: "hsl(var(--primary-foreground))",
                            boxShadow: "0 0 32px -8px hsl(var(--rust) / 0.5)",
                          }}
                        >
                          <Play className="w-5 h-5" />
                          Run AI Forensics
                        </motion.button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Navigation buttons */}
                <div className="flex items-center justify-between mt-6 pt-4 border-t" style={{ borderColor: "hsl(var(--border))" }}>
                  <button
                    onClick={() => setStep(s => Math.max(1, s - 1) as WorkflowStep)}
                    disabled={step === 1}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-30"
                    style={{ color: "hsl(var(--muted-foreground))" }}
                  >
                    <ArrowLeft className="w-4 h-4" /> Back
                  </button>

                  {step < 3 && (
                    <button
                      onClick={() => setStep(s => Math.min(3, s + 1) as WorkflowStep)}
                      disabled={!canProceed}
                      className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold transition-all disabled:opacity-30"
                      style={{
                        background: canProceed ? "hsl(var(--rust))" : "hsl(var(--muted))",
                        color: canProceed ? "hsl(var(--primary-foreground))" : "hsl(var(--muted-foreground))",
                      }}
                    >
                      Continue <ArrowRight className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            </motion.div>
          ) : (
            /* ═══ DASHBOARD VIEW ═══ */
            <motion.div
              key="dashboard"
              initial="hidden"
              animate="visible"
              variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.07 } } }}
              className="space-y-6 mt-4"
            >
              {/* Progress bar during scan */}
              {scanStatus === "scanning" && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="glass-panel rounded-xl p-5"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin" style={{ color: "hsl(var(--rust))" }} />
                      <span className="font-semibold text-sm" style={{ color: "hsl(var(--foreground))" }}>
                        Analysis in Progress
                      </span>
                    </div>
                    <span className="text-sm font-display" style={{ color: "hsl(var(--rust))" }}>
                      {Math.round(scanProgress)}%
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: "linear-gradient(90deg, hsl(var(--rust-dim)), hsl(var(--rust)))" }}
                      animate={{ width: `${scanProgress}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                </motion.div>
              )}

              {/* Error banner */}
              {scanStatus === "error" && scanError && (
                <div
                  className="glass-panel rounded-xl p-5 border"
                  style={{ borderColor: "hsl(var(--destructive))", background: "hsl(var(--destructive) / 0.05)" }}
                >
                  <p className="text-sm font-semibold" style={{ color: "hsl(var(--destructive))" }}>
                    Analysis Error: {scanError}
                  </p>
                  <button
                    onClick={() => { setShowDashboard(false); setScanStatus("idle"); setStep(1); }}
                    className="mt-2 text-xs underline"
                    style={{ color: "hsl(var(--muted-foreground))" }}
                  >
                    ← Back to setup
                  </button>
                </div>
              )}

              {/* Verdict banner */}
              {scanStatus === "complete" && snapshotData && (
                <motion.div
                  variants={{ hidden: { opacity: 0, y: -10 }, visible: { opacity: 1, y: 0 } }}
                  className="rounded-xl px-6 py-4 flex items-center justify-between"
                  style={{
                    background: (snapshotData.threats > 0)
                      ? "linear-gradient(135deg, hsl(var(--destructive) / 0.12), hsl(var(--threat-high) / 0.08))"
                      : "linear-gradient(135deg, hsl(var(--status-complete) / 0.12), hsl(var(--status-complete) / 0.05))",
                    border: `1px solid ${snapshotData.threats > 0 ? "hsl(var(--destructive) / 0.3)" : "hsl(var(--status-complete) / 0.3)"}`,
                  }}
                >
                  <div className="flex items-center gap-3">
                    {snapshotData.threats > 0 ? (
                      <AlertTriangle className="w-5 h-5" style={{ color: "hsl(var(--threat-critical))" }} />
                    ) : (
                      <CheckCircle2 className="w-5 h-5" style={{ color: "hsl(var(--status-complete))" }} />
                    )}
                    <div>
                      <span
                        className="font-display text-base font-bold"
                        style={{ color: snapshotData.threats > 0 ? "hsl(var(--threat-critical))" : "hsl(var(--status-complete))" }}
                      >
                        {snapshotData.threats > 0 ? "THREATS DETECTED" : "CLEAN"}
                      </span>
                      <p className="text-xs mt-0.5" style={{ color: "hsl(var(--muted-foreground))" }}>
                        Scanned {selectedDrive || "—"} with {selectedModels.size} model(s) in {snapshotData.executionTime} · {snapshotData.totalFiles} files analyzed · {snapshotData.threats} threat(s)
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => { setShowDashboard(false); setScanStatus("idle"); setStep(1); setScanProgress(0); }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all"
                      style={{
                        background: "hsl(var(--muted) / 0.6)",
                        color: "hsl(var(--foreground))",
                        border: "1px solid hsl(var(--border))",
                      }}
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      New Scan
                    </button>
                  </div>
                </motion.div>
              )}

              {/* Stats row */}
              <motion.div
                variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}
                className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4"
              >
                <StatCard
                  label="Confidence"
                  value={snapshotData?.confidence ?? "—"}
                  icon={TrendingUp}
                  color="hsl(var(--rust))"
                  gauge={snapshotData?.confidence}
                  description="ML classifier certainty"
                />
                <StatCard
                  label="Files Indexed"
                  value={snapshotData?.totalFiles ?? "—"}
                  icon={Files}
                  color="hsl(var(--foreground))"
                  description="Total file objects"
                />
                <StatCard
                  label="Threats Found"
                  value={snapshotData?.threats ?? "—"}
                  icon={ShieldAlert}
                  color="hsl(var(--threat-critical))"
                  description="IOC & malware matches"
                />
                <StatCard
                  label="Execution Time"
                  value={snapshotData?.executionTime ?? "—"}
                  icon={Clock}
                  color="hsl(var(--sand))"
                  description="Full pipeline duration"
                />
                <StatCard
                  label="Active Pipelines"
                  value={scanStatus === "scanning" ? stages.filter(s => s.status === "running").length : stages.length}
                  icon={Activity}
                  color="hsl(var(--status-complete))"
                  description={scanStatus === "scanning" ? "Currently running" : "Completed stages"}
                />
              </motion.div>

              {/* Two-column: Pipeline + AI Summary */}
              <motion.div
                variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}
                className="grid grid-cols-1 lg:grid-cols-2 gap-6"
              >
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="section-label">Analysis Pipeline</span>
                    <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                  </div>
                  <PipelineStatus stages={stages} loading={loading} />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="section-label">AI Analyst</span>
                    <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                  </div>
                  <AISummaryCard summary={aiSummary} riskBreakdown={riskBreakdown} loading={loading} />
                </div>
              </motion.div>

              {/* Threat Ledger */}
              <motion.div variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">Threat Intelligence</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                <ThreatLedger threats={threats} loading={loading} />
              </motion.div>

              {/* File Inventory — only flagged files (MEDIUM/HIGH/CRITICAL) */}
              <motion.div variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">Flagged Evidence ({files.length})</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                {files.length > 0 ? (
                  <FileInventory files={files} loading={loading} />
                ) : (
                  <div className="glass-panel rounded-xl p-6 text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
                    <p className="text-sm">No files flagged as threats — all files are LOW risk.</p>
                  </div>
                )}
              </motion.div>

              {/* Action Toolbar — Report Downloads + New Scan */}
              {scanStatus === "complete" && currentJobId && (
                <motion.div
                  variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}
                  className="glass-panel rounded-xl px-5 py-3.5 flex items-center justify-between"
                  style={{ borderLeft: "3px solid hsl(var(--rust))" }}
                >
                  <span className="section-label">Export Report</span>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={async () => {
                        try {
                          await masterAgentAPI.downloadPdfReport(currentJobId);
                          addLog(makeLog("info", "PDF report downloaded"));
                        } catch (e) {
                          addLog(makeLog("error", `PDF download failed: ${e}`));
                        }
                      }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all"
                      style={{
                        background: "hsl(var(--rust))",
                        color: "hsl(var(--primary-foreground))",
                      }}
                    >
                      <Download className="w-3.5 h-3.5" />
                      PDF Report
                    </button>
                    <button
                      onClick={async () => {
                        try {
                          await masterAgentAPI.downloadJsonReport(currentJobId);
                          addLog(makeLog("info", "JSON report downloaded"));
                        } catch (e) {
                          addLog(makeLog("error", `JSON download failed: ${e}`));
                        }
                      }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all"
                      style={{
                        background: "hsl(var(--muted) / 0.6)",
                        color: "hsl(var(--foreground))",
                        border: "1px solid hsl(var(--border))",
                      }}
                    >
                      <Download className="w-3.5 h-3.5" />
                      JSON
                    </button>
                  </div>
                </motion.div>
              )}

              {/* Log Stream */}
              <motion.div variants={{ hidden: { opacity: 0, y: 12 }, visible: { opacity: 1, y: 0 } }}>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">System Output</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                <AnalysisLogStream logs={logs} live={scanStatus === "scanning"} />
              </motion.div>

              {/* Footer */}
              <motion.div
                variants={{ hidden: { opacity: 0 }, visible: { opacity: 1 } }}
                className="flex items-center justify-between pt-4 pb-6 text-xs"
                style={{ color: "hsl(var(--muted-foreground))", borderTop: "1px solid hsl(var(--border) / 0.5)" }}
              >
                <span className="font-mono">Sentinel Forensics · v3.7.2 · NIST SP 800-86</span>
                <span className="font-mono">Chain of Custody: Preserved · SHA-256 verified</span>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
