import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  color: string;
  description?: string;
  /** 0-100, shows radial gauge if provided */
  gauge?: number;
}

function RadialGauge({ value, color }: { value: number; color: string }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;

  return (
    <div className="relative w-24 h-24">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={radius} fill="none" stroke="hsl(var(--border))" strokeWidth="6" />
        <motion.circle
          cx="48" cy="48" r={radius} fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="font-display text-xl" style={{ color }}>{value}%</span>
      </div>
    </div>
  );
}

export default function StatCard({ label, value, icon: Icon, color, description, gauge }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="glass-panel glass-panel-hover rounded-xl p-5 relative overflow-hidden"
    >
      {/* Top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-0.5"
        style={{ background: `linear-gradient(90deg, ${color}, transparent)` }}
      />

      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-3">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: `${color}15`, border: `1px solid ${color}25` }}
            >
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <span className="section-label">{label}</span>
          </div>

          {gauge !== undefined ? (
            <div className="flex items-center gap-4">
              <RadialGauge value={gauge} color={color} />
              {description && (
                <p className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>{description}</p>
              )}
            </div>
          ) : (
            <>
              <div className="metric-value" style={{ color }}>{typeof value === "number" ? value.toLocaleString() : value}</div>
              {description && (
                <p className="text-xs mt-1.5" style={{ color: "hsl(var(--muted-foreground))" }}>{description}</p>
              )}
            </>
          )}
        </div>
      </div>
    </motion.div>
  );
}
