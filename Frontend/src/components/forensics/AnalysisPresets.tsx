import { motion } from "framer-motion";
import { Zap, Scale, Search, SlidersHorizontal } from "lucide-react";
import { PRESETS, type PresetKey } from "@/hooks/useForensicsApi";

const PRESET_ICONS: Record<PresetKey, React.ReactNode> = {
  quick: <Zap className="w-4 h-4" />,
  balanced: <Scale className="w-4 h-4" />,
  deep: <Search className="w-4 h-4" />,
  custom: <SlidersHorizontal className="w-4 h-4" />,
};

interface AnalysisPresetsProps {
  active: PresetKey;
  onSelect: (key: PresetKey) => void;
}

export default function AnalysisPresets({ active, onSelect }: AnalysisPresetsProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-4">
        <h2 className="font-display text-xl mb-1" style={{ color: "hsl(var(--foreground))" }}>
          Analysis Profile
        </h2>
        <p className="text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>
          Choose a preset or customize your model selection
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {PRESETS.map((preset) => {
          const isActive = active === preset.key;
          return (
            <motion.button
              key={preset.key}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => onSelect(preset.key)}
              className="text-left rounded-xl p-4 transition-all duration-200"
              style={{
                background: isActive ? "hsl(var(--rust) / 0.08)" : "hsl(var(--slate-panel))",
                border: isActive
                  ? "1.5px solid hsl(var(--rust) / 0.5)"
                  : "1px solid hsl(var(--border))",
                boxShadow: isActive ? "0 0 20px -8px hsl(var(--rust) / 0.2)" : "none",
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <span style={{ color: isActive ? "hsl(var(--rust))" : "hsl(var(--muted-foreground))" }}>
                  {PRESET_ICONS[preset.key]}
                </span>
                <span
                  className="font-semibold text-sm"
                  style={{ color: isActive ? "hsl(var(--foreground))" : "hsl(var(--foreground) / 0.8)" }}
                >
                  {preset.label}
                </span>
              </div>
              <p className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                {preset.description}
              </p>
              {preset.key !== "custom" && (
                <p className="text-xs mt-2" style={{ color: "hsl(var(--muted-foreground) / 0.7)" }}>
                  {preset.modelIds.length} models
                </p>
              )}
            </motion.button>
          );
        })}
      </div>
    </motion.div>
  );
}
