import React, { useState } from 'react';
import './AnalysisResults.css';

interface AnalysisResultsProps {
  jobId: string;
  results: any;
  modelsRun: Record<string, boolean>;
  onDownload?: (jobId: string) => void;
}

export const AnalysisResults: React.FC<AnalysisResultsProps> = ({
  jobId,
  results,
  modelsRun,
  onDownload
}) => {
  const [expandedModels, setExpandedModels] = useState<Set<string>>(new Set());

  const toggleExpand = (modelId: string) => {
    const newExpanded = new Set(expandedModels);
    if (newExpanded.has(modelId)) {
      newExpanded.delete(modelId);
    } else {
      newExpanded.add(modelId);
    }
    setExpandedModels(newExpanded);
  };

  if (!results) {
    return <div className="analysis-results empty">No results available</div>;
  }

  return (
    <div className="analysis-results">
      <div className="results-header">
        <h3>Analysis Results</h3>
        <div className="results-meta">
          <span className="job-id">Job: {jobId}</span>
          <span className="timestamp">{new Date().toLocaleString()}</span>
        </div>
      </div>

      <div className="results-summary">
        <h4>Summary</h4>
        {results.summary ? (
          <div className="summary-content">
            {typeof results.summary === 'string' ? (
              <p>{results.summary}</p>
            ) : (
              <ul>
                {Object.entries(results.summary).map(([key, value]) => (
                  <li key={key}>
                    <strong>{key}:</strong> {String(value)}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <p className="no-data">No summary available</p>
        )}
      </div>

      <div className="results-models">
        <h4>Model Results</h4>
        {Object.entries(modelsRun).map(([modelId, wasRun]) =>
          wasRun ? (
            <div key={modelId} className="model-result">
              <button
                className="model-result-header"
                onClick={() => toggleExpand(modelId)}
              >
                <span className="expand-icon">
                  {expandedModels.has(modelId) ? '▼' : '▶'}
                </span>
                <span className="model-name">
                  {modelId.charAt(0).toUpperCase() + modelId.slice(1)} Model
                </span>
                <span className="result-status">
                  {results[modelId]
                    ? `✓ ${Object.keys(results[modelId] || {}).length} findings`
                    : 'No results'}
                </span>
              </button>

              {expandedModels.has(modelId) && (
                <div className="model-result-content">
                  {results[modelId] ? (
                    <pre className="result-data">
                      {JSON.stringify(results[modelId], null, 2)}
                    </pre>
                  ) : (
                    <p className="no-data">No detailed results available</p>
                  )}
                </div>
              )}
            </div>
          ) : null
        )}
      </div>

      {results.raw_output && (
        <div className="raw-output">
          <h4>Raw Output</h4>
          <pre>{results.raw_output}</pre>
        </div>
      )}

      <div className="results-actions">
        {onDownload && (
          <button
            className="download-btn"
            onClick={() => onDownload(jobId)}
          >
            ⬇ Download Report
          </button>
        )}
        <button
          className="copy-btn"
          onClick={() => {
            navigator.clipboard.writeText(JSON.stringify(results, null, 2));
            alert('Results copied to clipboard');
          }}
        >
          📋 Copy Results
        </button>
      </div>
    </div>
  );
};

export default AnalysisResults;
