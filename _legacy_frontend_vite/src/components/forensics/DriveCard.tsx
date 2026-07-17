import { HardDrive, Usb, Disc } from "lucide-react";
import { motion } from "framer-motion";
import type { DriveInfo } from "@/hooks/useForensicsApi";

const TYPE_ICONS = {
  local: HardDrive,
  external: Usb,
  image: Disc,
};

const TYPE_LABELS = {
  local: "Local",
  external: "External",
  image: "Image",
};

interface DriveCardProps {
  drive: DriveInfo;
  selected: boolean;
  onSelect: () => void;
}

export default function DriveCard({ drive, selected, onSelect }: DriveCardProps) {
  const Icon = TYPE_ICONS[drive.type];

  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onSelect}
      className="w-full text-left rounded-xl p-4 transition-all duration-200"
      style={{
        background: selected ? "hsl(var(--rust) / 0.08)" : "hsl(var(--slate-panel))",
        border: selected
          ? "1.5px solid hsl(var(--rust) / 0.5)"
          : "1px solid hsl(var(--border))",
        boxShadow: selected ? "0 0 24px -8px hsl(var(--rust) / 0.2)" : "none",
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{
            background: selected ? "hsl(var(--rust) / 0.15)" : "hsl(var(--muted))",
            border: `1px solid ${selected ? "hsl(var(--rust) / 0.3)" : "hsl(var(--border))"}`,
          }}
        >
          <Icon className="w-5 h-5" style={{ color: selected ? "hsl(var(--rust))" : "hsl(var(--muted-foreground))" }} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold text-sm" style={{ color: "hsl(var(--foreground))" }}>
              {drive.letter}
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded-full"
              style={{
                background: "hsl(var(--muted))",
                color: "hsl(var(--muted-foreground))",
                border: "1px solid hsl(var(--border))",
              }}
            >
              {TYPE_LABELS[drive.type]}
            </span>
          </div>
          <p className="text-sm" style={{ color: "hsl(var(--foreground) / 0.8)" }}>{drive.label}</p>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>{drive.size}</span>
            <span className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>{drive.description}</span>
          </div>
        </div>

        {/* Selection indicator */}
        <div
          className="w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-1 transition-colors"
          style={{
            borderColor: selected ? "hsl(var(--rust))" : "hsl(var(--border))",
            background: selected ? "hsl(var(--rust))" : "transparent",
          }}
        >
          {selected && (
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              className="w-2 h-2 rounded-full"
              style={{ background: "hsl(var(--primary-foreground))" }}
            />
          )}
        </div>
      </div>
    </motion.button>
  );
}
