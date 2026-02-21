export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

/* ── Types ─────────────────────────────────────────── */

export type DrivesResponse = {
  drives: string[];
  default_path?: string | null;
};

export type ModelOption = {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  enabled: boolean;
};

export type ModelsResponse = {
  models: Record<string, ModelOption>;
};

/* ── Helpers ───────────────────────────────────────── */

const handleResponse = async <T>(response: Response): Promise<T> => {
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
};

/* ── API Calls ─────────────────────────────────────── */

/** Get available system drives from backend */
export const fetchDrives = async (): Promise<DrivesResponse> => {
  const response = await fetch(`${API_BASE}/api/drives`);
  return handleResponse(response);
};

/** Get available forensic models from backend */
export const fetchModels = async (): Promise<ModelsResponse> => {
  const response = await fetch(`${API_BASE}/api/master-agent/models`);
  return handleResponse(response);
};

/** Health check */
export const fetchHealth = async (): Promise<{ status: string; models_loaded: string[] }> => {
  const response = await fetch(`${API_BASE}/health`);
  return handleResponse(response);
};
