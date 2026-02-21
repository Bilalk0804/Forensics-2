import React, { useState } from 'react';
import { masterAgentAPI } from '@/lib/masterAgentAPI';
import './AnalysisRunner.css';

interface AnalysisRunnerProps {
  selectedModels: Record<string, boolean>;
  onAnalysisStart?: (jobId: string) => void;
  onAnalysisComplete?: (jobId: string, results: any) => void;
  onError?: (error: string) => void;
}

export const AnalysisRunner: React.FC<AnalysisRunnerProps> = ({
  selectedModels,
  onAnalysisStart,
  onAnalysisComplete,
  onError
}) => {
  const [evidencePath, setEvidencePath] = useState('');
  const [outputPath, setOutputPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('');

  const selectedCount = Object.values(selectedModels).filter(Boolean).length;
  const canRunAnalysis = selectedCount > 0 && evidencePath.trim().length > 0;

  const handleRunAnalysis = async () => {
    if (!canRunAnalysis) {
      onError?.('Please select at least one model and provide an evidence path');
      return;
    }

    try {
      setLoading(true);
      setStatus('Starting analysis...');
      setProgress(0);

      // Start analysis
      const activeModels = Object.entries(selectedModels)
        .filter(([, v]) => v)
        .map(([k]) => k);
      const result = await masterAgentAPI.startAnalysis({
        evidencePath: evidencePath.trim(),
        selectedModels: activeModels,
        outputPath: outputPath.trim() || undefined,
      });

      if (!result.jobId) {
        throw new Error('Failed to start analysis — no job ID returned');
      }

      const jobId = result.jobId;
      setCurrentJobId(jobId);
      setStatus(`Analysis job started: ${jobId}`);
      setProgress(10);

      onAnalysisStart?.(jobId);

      // Poll for completion
      const completedJob = await masterAgentAPI.waitForCompletion(jobId);

      if (completedJob.status === 'completed') {
        setProgress(100);
        setStatus('Analysis completed successfully');
        onAnalysisComplete?.(jobId, completedJob.results);
      } else if (completedJob.status === 'failed') {
        throw new Error(completedJob.error || 'Analysis failed');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      setStatus(`Error: ${errorMessage}`);
      onError?.(errorMessage);
      setProgress(0);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="analysis-runner">
      <div className="runner-header">
        <h3>Configure & Run Analysis</h3>
      </div>

      <div className="runner-content">
        {/* Evidence Path Input */}
        <div className="input-group">
          <label htmlFor="evidence-path" className="input-label">
            Evidence Path
            <span className="required">*</span>
          </label>
          <input
            id="evidence-path"
            type="text"
            placeholder="e.g., /mnt/evidence or C:\Evidence"
            value={evidencePath}
            onChange={(e) => setEvidencePath(e.target.value)}
            disabled={loading}
            className="input-field"
          />
          <small className="input-hint">
            Path to the directory containing evidence files to analyze
          </small>
        </div>

        {/* Output Path Input */}
        <div className="input-group">
          <label htmlFor="output-path" className="input-label">
            Output Path (Optional)
          </label>
          <input
            id="output-path"
            type="text"
            placeholder="e.g., /mnt/output or C:\Output"
            value={outputPath}
            onChange={(e) => setOutputPath(e.target.value)}
            disabled={loading}
            className="input-field"
          />
          <small className="input-hint">
            Path where results will be saved (defaults to backend output directory)
          </small>
        </div>

        {/* Model Summary */}
        <div className="model-summary">
          <h4>Selected Models ({selectedCount})</h4>
          <div className="selected-models">
            {Object.entries(selectedModels).map(([model, selected]) =>
              selected ? (
                <span key={model} className="model-badge">
                  {model.charAt(0).toUpperCase() + model.slice(1)}
                  <span className="checkmark">✓</span>
                </span>
              ) : null
            )}
          </div>
          {selectedCount === 0 && (
            <p className="warning">Please select at least one model above</p>
          )}
        </div>

        {/* Status Display */}
        {loading && (
          <div className="status-box">
            <div className="spinner"></div>
            <p className="status-text">{status}</p>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            {currentJobId && (
              <p className="job-id">Job ID: {currentJobId}</p>
            )}
          </div>
        )}

        {status && !loading && (
          <div className={`status-box ${status.includes('Error') ? 'error' : 'success'}`}>
            <p className="status-text">{status}</p>
          </div>
        )}
      </div>

      <div className="runner-footer">
        <button
          onClick={handleRunAnalysis}
          disabled={!canRunAnalysis || loading}
          className="run-button"
        >
          {loading ? (
            <>
              <span className="spinner-small"></span>
              Running Analysis...
            </>
          ) : (
            <>
              🚀 Run Analysis ({selectedCount} model{selectedCount !== 1 ? 's' : ''})
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default AnalysisRunner;
