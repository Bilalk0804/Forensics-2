export const formatBytes = (value?: number) => {
  if (value === undefined || value === null) {
    return "-";
  }
  if (value === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.floor(Math.log(value) / Math.log(1024));
  const size = value / Math.pow(1024, index);
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
};

export const formatSeconds = (value?: number) => {
  if (!value && value !== 0) {
    return "-";
  }
  if (value < 60) {
    return `${value.toFixed(1)}s`;
  }
  const minutes = Math.floor(value / 60);
  const seconds = value % 60;
  return `${minutes}m ${seconds.toFixed(0)}s`;
};

export const formatConfidence = (value?: number) => {
  if (!value && value !== 0) {
    return "-";
  }
  const percent = value <= 1 ? value * 100 : value;
  return `${percent.toFixed(1)}%`;
};
