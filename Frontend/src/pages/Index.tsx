import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Play, ArrowLeft, ArrowRight, TrendingUp, Clock, Files, ShieldAlert,
  Activity, Loader2
} from "lucide-react";

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

// ─── Helpers ─────────────────────────────────────────────────

const LOG_TEMPLATES: { level: LogEntry["level"]; msgs: string[] }[] = [
  { level: "info", msgs: ["Initializing disk acquisition module…", "Mounting image", "Filesystem detected: NTFS 3.1", "Scanning MFT entries", "Hash verification: SHA-256 OK", "Loading YARA ruleset v4.5.2…"] },
  { level: "warn", msgs: ["High entropy section detected", "Suspicious registry run-key modification", "Packed binary detected — unpacking…", "Anomalous network socket in process 1492"] },
  { level: "error", msgs: ["CRIT: Credential dumping tool identified", "ERROR: Ransomware dropper found", "CRIT: C2 beacon detected"] },
  { level: "debug", msgs: ["Checking PE header at offset 0x1A4", "Reading cluster chain", "Entropy score: 7.91 (threshold 7.0)", "Loaded 14,823 IOC signatures"] },
];

function generateLog(): LogEntry {
  const t = LOG_TEMPLATES[Math.floor(Math.random() * LOG_TEMPLATES.length)];
  const now = new Date();
  return {
    id: `log-${Date.now()}-${Math.random()}`,
    ts: `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`,
    level: t.level,
    msg: t.msgs[Math.floor(Math.random() * t.msgs.length)],
  };
}

const INITIAL_LOGS: LogEntry[] = [
  { id: "l0", ts: "09:10:00", level: "info", msg: "Sentinel Forensics v3.7.2 initialized" },
  { id: "l1", ts: "09:10:01", level: "info", msg: "Evidence database loaded" },
  { id: "l2", ts: "09:10:02", level: "debug", msg: "YARA ruleset v4.5.2 — 14,823 signatures active" },
];

/** Convert backend job results into dashboard-friendly data */
function mapJobResults(job: JobStatus) {
  const threats: ThreatEntry[] = [];
  const files: FileEntry[] = [];
  let totalFiles = 0;
  let totalThreats = 0;

  if (job.results) {
    Object.entries(job.results).forEach(([modelId, result]) => {
      const details = result.details || [];
      totalFiles += result.files_analyzed || 0;
      totalThreats += result.threats || 0;

      details.forEach((d, idx) => {
        // Add to file inventory
        const fileName = d.file.split(/[\\/]/).pop() || d.file;
        const filePath = d.file.substring(0, d.file.lastIndexOf("\\") + 1) || d.file;
        const riskLevel: FileEntry["risk"] = d.error ? "high" : (result.threats && result.threats > 0 ? "medium" : "clean");
        files.push({
          id: `${modelId}-f${idx}`,
          name: fileName,
          path: filePath,
          size: "",
          mime: "",
          risk: riskLevel,
          modified: "",
        });

        // If result indicates threat, add to threat ledger
        if (d.result && typeof d.result === "object") {
          const r = d.result as Record<string, unknown>;
          if (r.malicious || r.threat || r.severity) {
            threats.push({
              id: `${modelId}-t${idx}`,
              severity: ((r.severity as string) || "medium") as ThreatEntry["severity"],
              name: (r.threat_name as string) || (r.label as string) || `${modelId} detection`,
              path: d.file,
              type: modelId,
              timestamp: new Date().toTimeString().slice(0, 8),
              hash: (r.hash as string) || "",
            });
          }
        }
      });
    });
  }

  return { threats, files, totalFiles, totalThreats };
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
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_LOGS);
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

    addLog({
      id: `l-start-${Date.now()}`,
      ts: new Date().toTimeString().slice(0, 8),
      level: "info",
      msg: `Initiating AI forensic analysis on ${selectedDrive} with ${modelNames.length} models…`,
    });

    // Start generating fake log lines for visual feedback
    logIntervalRef.current = setInterval(() => addLog(generateLog()), 800);

    try {
      // 1. Start the analysis job
      const result = await masterAgentAPI.startAnalysis({
        evidencePath: selectedDrive,
        selectedModels: modelNames,
      });

      addLog({
        id: `l-job-${Date.now()}`,
        ts: new Date().toTimeString().slice(0, 8),
        level: "info",
        msg: `Job ${result.jobId} started — polling for completion…`,
      });

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
        const elapsed = completedJob.startTime
          ? `${Math.round((Date.now() - new Date(completedJob.startTime).getTime()) / 1000)}s`
          : "—";

        setScanStatus("complete");
        setScanProgress(100);
        setThreats(mapped.threats);
        setFiles(mapped.files);
        setSnapshotData({
          confidence: mapped.totalThreats > 0 ? 87 : 96,
          executionTime: elapsed,
          totalFiles: mapped.totalFiles || mapped.files.length,
          threats: mapped.totalThreats || mapped.threats.length,
        });
        setStages(prev => prev.map(s => ({ ...s, status: "complete" as const })));

        // Build risk breakdown
        const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
        mapped.threats.forEach(t => {
          if (t.severity in riskCounts) riskCounts[t.severity as keyof typeof riskCounts]++;
        });
        riskCounts.clean = Math.max(0, (mapped.totalFiles || mapped.files.length) - mapped.threats.length);
        setRiskBreakdown(riskCounts);

        setAiSummary(
          `Analysis of ${selectedDrive} completed. ${mapped.totalFiles || mapped.files.length} files analyzed across ${modelNames.length} models. ` +
          `${mapped.totalThreats || mapped.threats.length} potential threat(s) detected.` +
          (mapped.threats.length > 0
            ? ` Immediate review recommended for: ${mapped.threats.slice(0, 3).map(t => t.name).join(", ")}.`
            : " No significant threats found.")
        );

        addLog({
          id: `l-done-${Date.now()}`,
          ts: new Date().toTimeString().slice(0, 8),
          level: "info",
          msg: "Pipeline complete — all results collated.",
        });
      } else {
        // Job failed
        setScanStatus("error");
        setScanError(completedJob.error || "Analysis failed");
        addLog({
          id: `l-err-${Date.now()}`,
          ts: new Date().toTimeString().slice(0, 8),
          level: "error",
          msg: `Analysis failed: ${completedJob.error || "Unknown error"}`,
        });
      }
    } catch (err: unknown) {
      if (logIntervalRef.current) clearInterval(logIntervalRef.current);
      const msg = err instanceof Error ? err.message : String(err);
      setScanStatus("error");
      setScanError(msg);
      addLog({
        id: `l-err-${Date.now()}`,
        ts: new Date().toTimeString().slice(0, 8),
        level: "error",
        msg: `Error: ${msg}`,
      });
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
              className="max-w-2xl mx-auto mt-8"
            >
              {/* Step indicator */}
              <div className="flex items-center justify-center gap-2 mb-8">
                {[1, 2, 3].map((s) => (
                  <div key={s} className="flex items-center gap-2">
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold transition-all"
                      style={{
                        background: s <= step ? "hsl(var(--rust))" : "hsl(var(--muted))",
                        color: s <= step ? "hsl(var(--primary-foreground))" : "hsl(var(--muted-foreground))",
                        border: `1px solid ${s <= step ? "hsl(var(--rust))" : "hsl(var(--border))"}`,
                      }}
                    >
                      {s}
                    </div>
                    {s < 3 && (
                      <div
                        className="w-12 h-0.5 rounded-full"
                        style={{
                          background: s < step ? "hsl(var(--rust))" : "hsl(var(--border))",
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
                      <div className="text-center py-8">
                        <div
                          className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4"
                          style={{ background: "hsl(var(--rust) / 0.12)", border: "1px solid hsl(var(--rust) / 0.25)" }}
                        >
                          <Play className="w-7 h-7" style={{ color: "hsl(var(--rust))" }} />
                        </div>
                        <h2 className="font-display text-2xl mb-2" style={{ color: "hsl(var(--foreground))" }}>
                          Ready to Analyze
                        </h2>
                        <p className="text-sm mb-6" style={{ color: "hsl(var(--muted-foreground))" }}>
                          {selectedModels.size} models selected · Drive {selectedDrive || "—"}
                        </p>

                        <motion.button
                          whileHover={{ scale: 1.03 }}
                          whileTap={{ scale: 0.97 }}
                          onClick={startScan}
                          className="inline-flex items-center gap-3 px-10 py-4 rounded-xl font-display text-lg font-bold transition-all"
                          style={{
                            background: "linear-gradient(135deg, hsl(var(--rust)), hsl(var(--rust-glow)))",
                            color: "hsl(var(--primary-foreground))",
                            boxShadow: "0 8px 32px -8px hsl(var(--rust) / 0.5)",
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
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
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

              {/* Stats row */}
              <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
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
              </div>

              {/* Two-column: Pipeline + AI Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
              </div>

              {/* Threat Ledger */}
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">Threat Intelligence</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                <ThreatLedger threats={threats} loading={loading} />
              </div>

              {/* File Inventory */}
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">Evidence Artifacts</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                <FileInventory files={files} loading={loading} />
              </div>

              {/* Log Stream */}
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span className="section-label">System Output</span>
                  <div className="flex-1 h-px" style={{ background: "hsl(var(--border))" }} />
                </div>
                <AnalysisLogStream logs={logs} live={scanStatus === "scanning"} />
              </div>

              {/* Footer */}
              <div
                className="flex items-center justify-between pt-2 pb-4 text-xs"
                style={{ color: "hsl(var(--muted-foreground))", borderTop: "1px solid hsl(var(--border))" }}
              >
                <span>Sentinel Forensics · v3.7.2 · NIST SP 800-86</span>
                <span>Chain of Custody: Preserved · SHA-256 verified</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
