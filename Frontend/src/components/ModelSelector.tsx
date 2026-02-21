import React, { useEffect, useState } from 'react';
import { masterAgentAPI, type ModelOption } from '@/lib/masterAgentAPI';
import './ModelSelector.css';

interface ModelSelectorProps {
  onSelectModels: (models: Record<string, boolean>) => void;
  disabled?: boolean;
}

export const ModelSelector: React.FC<ModelSelectorProps> = ({
  onSelectModels,
  disabled = false
}) => {
  const [models, setModels] = useState<Record<string, ModelOption>>({});
  const [selectedModels, setSelectedModels] = useState<Record<string, boolean>>({
    vision: false,
    malware: false,
    text: false,
    deepfake: false,
    file: false
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchModels();
  }, []);

  const fetchModels = async () => {
    try {
      setLoading(true);
      setError(null);
      const availableModels = await masterAgentAPI.getAvailableModels();
      setModels(availableModels);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load models');
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = (modelId: string) => {
    const updated = {
      ...selectedModels,
      [modelId]: !selectedModels[modelId]
    };
    setSelectedModels(updated);
    onSelectModels(updated);
  };

  const selectAll = () => {
    const allSelected = Object.keys(models).reduce((acc, key) => {
      acc[key] = true;
      return acc;
    }, {} as Record<string, boolean>);
    setSelectedModels(allSelected);
    onSelectModels(allSelected);
  };

  const deselectAll = () => {
    const allDeselected = Object.keys(models).reduce((acc, key) => {
      acc[key] = false;
      return acc;
    }, {} as Record<string, boolean>);
    setSelectedModels(allDeselected);
    onSelectModels(allDeselected);
  };

  if (loading) {
    return (
      <div className="model-selector loading">
        <p>Loading available models...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="model-selector error">
        <p className="error-message">Error: {error}</p>
        <button onClick={fetchModels} className="retry-btn">
          Retry
        </button>
      </div>
    );
  }

  const anySelected = Object.values(selectedModels).some(v => v);

  return (
    <div className="model-selector">
      <div className="model-selector-header">
        <h3>Select Analysis Models</h3>
        <p className="subtitle">Choose which analysis pipelines to run</p>
      </div>

      <div className="model-selector-actions">
        <button
          onClick={selectAll}
          className="action-btn select-all"
          disabled={disabled}
        >
          Select All
        </button>
        <button
          onClick={deselectAll}
          className="action-btn deselect-all"
          disabled={disabled}
        >
          Deselect All
        </button>
      </div>

      <div className="models-grid">
        {Object.entries(models).map(([modelId, model]) => (
          <div
            key={modelId}
            className={`model-card ${selectedModels[modelId] ? 'selected' : ''} ${!model.enabled ? 'disabled' : ''}`}
          >
            <input
              type="checkbox"
              id={`model-${modelId}`}
              checked={selectedModels[modelId]}
              onChange={() => handleToggle(modelId)}
              disabled={disabled || !model.enabled}
              className="model-checkbox"
            />
            <label htmlFor={`model-${modelId}`} className="model-label">
              <div className="model-name">{model.name}</div>
              <div className="model-description">{model.description}</div>
              <div className="model-capabilities">
                {model.capabilities.map((cap, idx) => (
                  <span key={idx} className="capability-badge">
                    {cap.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </label>
          </div>
        ))}
      </div>

      {!anySelected && (
        <div className="warning-box">
          ⚠️ Please select at least one model to proceed with analysis.
        </div>
      )}
    </div>
  );
};

export default ModelSelector;
