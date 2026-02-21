/**
 * API Service for Master Agent
 * Handles communication with the FastAPI backend endpoints
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE || 'http://localhost:8000';
const MASTER_AGENT_BASE = `${API_BASE_URL}/api/master-agent`;

export interface ModelOption {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  enabled: boolean;
}

export interface AnalysisConfig {
  evidencePath: string;
  selectedModels: string[];
  outputPath?: string;
}

export interface AnalysisResult {
  jobId: string;
  status: string;
  message?: string;
}

export interface JobStatus {
  jobId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  results?: Record<string, {
    status: string;
    files_analyzed?: number;
    threats?: number;
    details?: Array<{
      file: string;
      result?: any;
      error?: string;
    }>;
  }>;
  error?: string | null;
  config?: {
    evidencePath: string;
    outputPath?: string;
    selectedModels: string[];
  };
  startTime?: string;
}

class MasterAgentAPI {
  /**
   * Fetch available models from API
   */
  async getAvailableModels(): Promise<Record<string, ModelOption>> {
    const response = await fetch(`${MASTER_AGENT_BASE}/models`);
    if (!response.ok) {
      throw new Error(`Failed to fetch models: ${response.statusText}`);
    }
    const data = await response.json();
    return data.models;
  }

  /**
   * Start a new analysis job.
   * Backend expects: { evidencePath: string, selectedModels: string[], outputPath?: string }
   */
  async startAnalysis(config: AnalysisConfig): Promise<AnalysisResult> {
    const response = await fetch(`${MASTER_AGENT_BASE}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        evidencePath: config.evidencePath,
        selectedModels: config.selectedModels,
        outputPath: config.outputPath || null,
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || error.error || `Analysis failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get job status and results
   */
  async getJobStatus(jobId: string): Promise<JobStatus> {
    const response = await fetch(`${MASTER_AGENT_BASE}/status/${jobId}`);
    if (!response.ok) {
      throw new Error(`Failed to get job status: ${response.statusText}`);
    }
    return response.json();
  }

  /**
   * Get all active jobs
   */
  async getAllJobs(): Promise<JobStatus[]> {
    const response = await fetch(`${MASTER_AGENT_BASE}/jobs`);
    if (!response.ok) {
      throw new Error(`Failed to fetch jobs: ${response.statusText}`);
    }
    const data = await response.json();
    return data.jobs;
  }

  /**
   * Delete/cancel a job
   */
  async deleteJob(jobId: string): Promise<void> {
    const response = await fetch(`${MASTER_AGENT_BASE}/jobs/${jobId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error(`Failed to delete job: ${response.statusText}`);
    }
  }

  /**
   * Poll for job completion with timeout.
   * Default: 30 minutes max wait, 5-second poll interval (HF models are slow).
   */
  async waitForCompletion(
    jobId: string,
    onProgress?: (job: JobStatus) => void,
    maxWaitMs = 1800000, // 30 minutes
    pollIntervalMs = 5000 // 5 seconds
  ): Promise<JobStatus> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitMs) {
      const job = await this.getJobStatus(jobId);

      // Report progress to caller
      if (onProgress) {
        onProgress(job);
      }

      if (job.status === 'completed' || job.status === 'failed') {
        return job;
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }

    throw new Error(`Job ${jobId} did not complete within ${maxWaitMs / 60000} minutes`);
  }
}

export const masterAgentAPI = new MasterAgentAPI();
