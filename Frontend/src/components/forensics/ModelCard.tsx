import { motion } from "framer-motion";
import { Check } from "lucide-react";
import type { ModelInfo } from "@/hooks/useForensicsApi";

const SPEED_CLASSES: Record<string, string> = {
  Fast: "speed-fast",
  Balanced: "speed-balanced",
  Accurate: "speed-accurate",
};

interface ModelCardProps {
  model: ModelInfo;
  selected: boolean;
  onToggle: () => void;
}

export default function ModelCard({ model, selected, onToggle }: ModelCardProps) {
  return (
    <motion.button
      whileHover={{ scale: 1.01 }}
      whileTap={{ scale: 0.99 }}
      onClick={onToggle}
      className="w-full text-left rounded-xl p-3.5 transition-all duration-200"
      style={{
        background: selected ? "hsl(var(--rust) / 0.06)" : "hsl(var(--slate-panel))",
        border: selected
          ? "1.5px solid hsl(var(--rust) / 0.4)"
          : "1px solid hsl(var(--border))",
      }}
    >
      <div className="flex items-center gap-3">
        {/* Checkbox */}
        <div
          className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 transition-colors"
          style={{
            background: selected ? "hsl(var(--rust))" : "transparent",
            border: `1.5px solid ${selected ? "hsl(var(--rust))" : "hsl(var(--border))"}`,
          }}
        >
          {selected && <Check className="w-3 h-3" style={{ color: "hsl(var(--primary-foreground))" }} />}
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <span className="text-sm font-medium block" style={{ color: "hsl(var(--foreground))" }}>
            {model.name}
          </span>
        </div>

        {/* Badges */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SPEED_CLASSES[model.speed]}`}>
            {model.speed}
          </span>
          <span
            className="text-xs px-2 py-0.5 rounded-full"
            style={{
              background: "hsl(var(--muted))",
              color: "hsl(var(--muted-foreground))",
              border: "1px solid hsl(var(--border))",
            }}
          >
            {model.vram}
          </span>
        </div>
      </div>
    </motion.button>
  );
}
