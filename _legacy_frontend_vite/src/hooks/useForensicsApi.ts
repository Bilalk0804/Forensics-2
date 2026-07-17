/**
 * Forensics API types and presets.
 * Mock data removed — drives and models are now fetched from the backend.
 */

export type PresetKey = "quick" | "balanced" | "deep" | "custom";

export interface Preset {
  key: PresetKey;
  label: string;
  description: string;
  /** Backend model IDs: vision, text, malware, file, audio, deepfake */
  modelIds: string[];
}

export const PRESETS: Preset[] = [
  {
    key: "quick",
    label: "Quick Scan",
    description: "Fast sweep — text + file analysis only",
    modelIds: ["text", "file"],
  },
  {
    key: "balanced",
    label: "Balanced Forensics",
    description: "Recommended for most investigations",
    modelIds: ["vision", "text", "malware", "file"],
  },
  {
    key: "deep",
    label: "Deep Investigation",
    description: "Maximum accuracy, all models active",
    modelIds: ["vision", "text", "malware", "file", "audio", "deepfake"],
  },
  {
    key: "custom",
    label: "Custom",
    description: "Select models manually",
    modelIds: [],
  },
];
