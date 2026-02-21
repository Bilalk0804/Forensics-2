import { motion } from "framer-motion";
import type { ModelOption } from "@/lib/api";

interface ModelSelectionProps {
  models: Record<string, ModelOption>;
  selectedModels: Set<string>;
  onToggle: (id: string) => void;
  loading?: boolean;
}

const MODEL_ICONS: Record<string, string> = {
  vision: "👁️",
  text: "📝",
  malware: "🦠",
  file: "📋",
  audio: "🎧",
  deepfake: "🎭",
};

export default function ModelSelection({ models, selectedModels, onToggle, loading }: ModelSelectionProps) {
  const entries = Object.entries(models);

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-4">
        <h2 className="font-display text-xl mb-1" style={{ color: "hsl(var(--foreground))" }}>
          Choose Analysis Models
        </h2>
        <p className="text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>
          Select AI models to run against the evidence · {selectedModels.size} selected
        </p>
      </div>

      {loading ? (
        <div className="py-8 text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
          <div className="inline-block w-6 h-6 border-2 border-current border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-sm">Loading models from backend…</p>
        </div>
      ) : entries.length === 0 ? (
        <div className="py-8 text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
          <p className="text-sm">No models available. Make sure the backend is running.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {entries.map(([id, model]) => {
            const selected = selectedModels.has(id);
            const disabled = !model.enabled;
            return (
              <motion.div
                key={id}
                whileHover={disabled ? {} : { scale: 1.01 }}
                whileTap={disabled ? {} : { scale: 0.99 }}
                onClick={() => !disabled && onToggle(id)}
                className="rounded-xl p-4 cursor-pointer transition-all"
                style={{
                  background: selected
                    ? "hsl(var(--rust) / 0.10)"
                    : "hsl(var(--muted) / 0.3)",
                  border: `1px solid ${selected ? "hsl(var(--rust) / 0.4)" : "hsl(var(--border))"
                    }`,
                  opacity: disabled ? 0.45 : 1,
                  cursor: disabled ? "not-allowed" : "pointer",
                }}
              >
                <div className="flex items-center gap-3">
                  {/* Checkbox */}
                  <div
                    className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 transition-all"
                    style={{
                      background: selected ? "hsl(var(--rust))" : "transparent",
                      border: selected
                        ? "none"
                        : "2px solid hsl(var(--muted-foreground) / 0.4)",
                    }}
                  >
                    {selected && (
                      <svg viewBox="0 0 12 12" className="w-3 h-3" fill="none">
                        <path d="M2 6l3 3 5-5" stroke="white" strokeWidth="2" />
                      </svg>
                    )}
                  </div>

                  <span className="text-xl">{MODEL_ICONS[id] || "🔬"}</span>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className="font-semibold text-sm"
                        style={{ color: "hsl(var(--foreground))" }}
                      >
                        {model.name}
                      </span>
                      {disabled && (
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded-full"
                          style={{
                            background: "hsl(var(--muted))",
                            color: "hsl(var(--muted-foreground))",
                          }}
                        >
                          Unavailable
                        </span>
                      )}
                    </div>
                    <p
                      className="text-xs mt-0.5 truncate"
                      style={{ color: "hsl(var(--muted-foreground))" }}
                    >
                      {model.description}
                    </p>
                  </div>
                </div>

                {/* Capabilities */}
                {model.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2 ml-8">
                    {model.capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="text-[10px] px-2 py-0.5 rounded-full"
                        style={{
                          background: selected
                            ? "hsl(var(--rust) / 0.15)"
                            : "hsl(var(--muted))",
                          color: selected
                            ? "hsl(var(--rust))"
                            : "hsl(var(--muted-foreground))",
                        }}
                      >
                        {cap.replace(/-/g, " ")}
                      </span>
                    ))}
                  </div>
                )}
              </motion.div>
            );
          })}
        </div>
      )}
    </motion.div>
  );
}
