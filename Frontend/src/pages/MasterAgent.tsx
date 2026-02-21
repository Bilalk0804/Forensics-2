import React, { useState } from 'react';
import ModelSelector from '../components/ModelSelector';
import AnalysisRunner from '../components/AnalysisRunner';
import AnalysisResults from '../components/AnalysisResults';
import './MasterAgent.css';

interface AnalysisState {
  jobId: string;
  results: any;
  modelsRun: Record<string, boolean>;
  timestamp: string;
}

export const MasterAgent: React.FC = () => {
  const [selectedModels, setSelectedModels] = useState<Record<string, boolean>>({
    vision: false,
    malware: false,
    text: false,
    deepfake: false,
    file: false
  });

  const [analysisState, setAnalysisState] = useState<AnalysisState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showResults, setShowResults] = useState(false);

  const handleModelsSelect = (models: Record<string, boolean>) => {
    setSelectedModels(models);
    setError(null);
  };

  const handleAnalysisStart = (jobId: string) => {
    console.log(`Analysis started with job ID: ${jobId}`);
  };

  const handleAnalysisComplete = (jobId: string, results: any) => {
    setAnalysisState({
      jobId,
      results,
      modelsRun: selectedModels,
      timestamp: new Date().toISOString()
    });
    setShowResults(true);
    setError(null);
  };

  const handleError = (error: string) => {
    setError(error);
    setShowResults(false);
  };

  const handleDownloadResults = (jobId: string) => {
    if (analysisState?.results) {
      const dataStr = JSON.stringify(analysisState.results, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `analysis_results_${jobId}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }
  };

  const handleReset = () => {
    setAnalysisState(null);
    setShowResults(false);
    setError(null);
    setSelectedModels({
      vision: false,
      malware: false,
      text: false,
      deepfake: false,
      file: false
    });
  };

  return (
    <div className="master-agent-page">
      <div className="page-header">
        <div className="header-content">
          <h1>🤖 Sentinel Master Agent</h1>
          <p className="subtitle">
            Intelligent forensic analysis orchestration with selective model execution
          </p>
        </div>
        <div className="header-stats">
          <div className="stat-card">
            <div className="stat-label">Selected Models</div>
            <div className="stat-value">
              {Object.values(selectedModels).filter(Boolean).length}
            </div>
          </div>
          {analysisState && (
            <div className="stat-card">
              <div className="stat-label">Status</div>
              <div className="stat-value success">✓ Complete</div>
            </div>
          )}
        </div>
      </div>

      <div className="page-content">
        {error && (
          <div className="error-alert">
            <div className="error-title">⚠️ Error</div>
            <p className="error-message">{error}</p>
            <button
              className="error-dismiss"
              onClick={() => setError(null)}
            >
              Dismiss
            </button>
          </div>
        )}

        {!showResults ? (
          <>
            {/* Model Selector */}
            <section className="section">
              <ModelSelector
                onSelectModels={handleModelsSelect}
                disabled={analysisState !== null}
              />
            </section>

            {/* Analysis Runner */}
            <section className="section">
              <AnalysisRunner
                selectedModels={selectedModels}
                onAnalysisStart={handleAnalysisStart}
                onAnalysisComplete={handleAnalysisComplete}
                onError={handleError}
              />
            </section>

            {/* Info Section */}
            <section className="info-section">
              <h3>How It Works</h3>
              <div className="info-grid">
                <div className="info-card">
                  <div className="info-number">1</div>
                  <h4>Select Models</h4>
                  <p>Choose which analysis models to execute based on your forensic needs.</p>
                </div>
                <div className="info-card">
                  <div className="info-number">2</div>
                  <h4>Configure Paths</h4>
                  <p>Specify the evidence directory path and optional output location.</p>
                </div>
                <div className="info-card">
                  <div className="info-number">3</div>
                  <h4>Run Analysis</h4>
                  <p>Execute the master agent which orchestrates all selected pipelines.</p>
                </div>
                <div className="info-card">
                  <div className="info-number">4</div>
                  <h4>Review Results</h4>
                  <p>View detailed findings from each model and download comprehensive reports.</p>
                </div>
              </div>
            </section>

            {/* Available Models Info */}
            <section className="models-info-section">
              <h3>Available Analysis Models</h3>
              <div className="models-info-grid">
                <div className="model-info-card">
                  <h4>👁️ Vision Detection</h4>
                  <p>YOLOv8-based object detection for forensic image analysis with risk classification and violence detection.</p>
                </div>
                <div className="model-info-card">
                  <h4>🦠 Malware Detection</h4>
                  <p>ML-based detection using PE header analysis and URL classification to identify malicious executables.</p>
                </div>
                <div className="model-info-card">
                  <h4>📝 Text/NLP Analysis</h4>
                  <p>OCR and natural language processing for text extraction, sensitive data detection, and suspicious content.</p>
                </div>
                <div className="model-info-card">
                  <h4>🎭 Deepfake Detection</h4>
                  <p>Synthetic media detection to identify deepfakes and authenticity verification of video/image content.</p>
                </div>
                <div className="model-info-card">
                  <h4>📋 File Integrity</h4>
                  <p>Header analysis and tampering detection to identify file mismatches and hidden or suspicious files.</p>
                </div>
              </div>
            </section>
          </>
        ) : analysisState ? (
          <>
            {/* Results Display */}
            <div className="results-section">
              <AnalysisResults
                jobId={analysisState.jobId}
                results={analysisState.results}
                modelsRun={analysisState.modelsRun}
                onDownload={handleDownloadResults}
              />

              <div className="results-actions">
                <button className="reset-btn" onClick={handleReset}>
                  ← Run New Analysis
                </button>
                <button
                  className="export-btn"
                  onClick={() => handleDownloadResults(analysisState.jobId)}
                >
                  📥 Export Results
                </button>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
};

export default MasterAgent;
