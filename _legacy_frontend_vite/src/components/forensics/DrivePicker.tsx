import { Upload } from "lucide-react";
import { motion } from "framer-motion";
import DriveCard from "./DriveCard";

interface DriveInfo {
  letter: string;
  label: string;
}

interface DrivePickerProps {
  drives: DriveInfo[];
  selectedDrive: string | null;
  onSelect: (drivePath: string) => void;
  loading?: boolean;
}

export default function DrivePicker({ drives, selectedDrive, onSelect, loading }: DrivePickerProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-4">
        <h2 className="font-display text-xl mb-1" style={{ color: "hsl(var(--foreground))" }}>
          Select Evidence Source
        </h2>
        <p className="text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>
          Choose a drive to analyze or enter an evidence path
        </p>
      </div>

      {loading ? (
        <div className="py-8 text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
          <div className="inline-block w-6 h-6 border-2 border-current border-t-transparent rounded-full animate-spin mb-2" />
          <p className="text-sm">Loading drives…</p>
        </div>
      ) : drives.length === 0 ? (
        <div className="py-8 text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
          <p className="text-sm">No drives detected. Enter a path manually below.</p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {drives.map((drive) => (
            <DriveCard
              key={drive.letter}
              drive={{
                id: drive.letter,
                label: drive.label,
                letter: drive.letter,
                size: "",
                type: "local" as const,
                description: "Local drive",
              }}
              selected={selectedDrive === drive.letter}
              onSelect={() => onSelect(drive.letter)}
            />
          ))}
        </div>
      )}

      {/* Manual path input */}
      <div className="mt-4">
        <label
          className="block text-xs font-medium mb-1.5"
          style={{ color: "hsl(var(--muted-foreground))" }}
        >
          Or enter evidence path manually:
        </label>
        <input
          type="text"
          placeholder="e.g., C:\Evidence or /mnt/evidence"
          value={selectedDrive && !drives.some(d => d.letter === selectedDrive) ? selectedDrive : ""}
          onChange={(e) => onSelect(e.target.value)}
          className="w-full rounded-lg px-3 py-2.5 text-sm transition-all outline-none"
          style={{
            background: "hsl(var(--muted) / 0.5)",
            border: "1px solid hsl(var(--border))",
            color: "hsl(var(--foreground))",
          }}
        />
      </div>
    </motion.div>
  );
}
