import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Upload, FileText, AlertTriangle, CheckCircle, Download, Loader2, X } from 'lucide-react';

const API_BASE = (import.meta.env.VITE_API_BASE || 'http://localhost:8000') + '/api/nlp';

interface FileInfo {
    name: string;
    size: number;
    file: File;
}

interface AnalysisResult {
    success: boolean;
    jobId: string;
    status: string;
    summary?: {
        files_analyzed: number;
        total_evidence: number;
        overall_risk: string;
        high_risk_files: string[];
    };
    reportPath?: string;
}

export default function NLPAnalysis() {
    const [files, setFiles] = useState<FileInfo[]>([]);
    const [uploading, setUploading] = useState(false);
    const [analyzing, setAnalyzing] = useState(false);
    const [jobId, setJobId] = useState<string | null>(null);
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [progress, setProgress] = useState(0);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        const droppedFiles = Array.from(e.dataTransfer.files);
        addFiles(droppedFiles);
    }, []);

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files) {
            addFiles(Array.from(e.target.files));
        }
    };

    const addFiles = (newFiles: File[]) => {
        const validExtensions = ['.pdf', '.docx', '.doc', '.csv', '.txt', '.json'];
        const validFiles = newFiles.filter(f =>
            validExtensions.some(ext => f.name.toLowerCase().endsWith(ext))
        );

        setFiles(prev => [
            ...prev,
            ...validFiles.map(f => ({ name: f.name, size: f.size, file: f }))
        ]);
        setError(null);
        setResult(null);
    };

    const removeFile = (index: number) => {
        setFiles(prev => prev.filter((_, i) => i !== index));
    };

    const formatFileSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    const uploadAndAnalyze = async () => {
        if (files.length === 0) return;

        setError(null);
        setResult(null);
        setProgress(10);

        try {
            // Step 1: Upload files
            setUploading(true);
            const formData = new FormData();
            files.forEach(f => formData.append('files', f.file));

            const uploadRes = await fetch(`${API_BASE}/upload`, {
                method: 'POST',
                body: formData
            });

            if (!uploadRes.ok) {
                throw new Error('Upload failed');
            }

            const uploadData = await uploadRes.json();
            setJobId(uploadData.jobId);
            setProgress(40);
            setUploading(false);

            // Step 2: Analyze
            setAnalyzing(true);
            const analyzeRes = await fetch(`${API_BASE}/analyze/${uploadData.jobId}`, {
                method: 'POST'
            });

            if (!analyzeRes.ok) {
                const errData = await analyzeRes.json();
                throw new Error(errData.error || 'Analysis failed');
            }

            const analyzeData = await analyzeRes.json();
            setProgress(100);
            setResult(analyzeData);
            setAnalyzing(false);

        } catch (err) {
            setError(err instanceof Error ? err.message : 'An error occurred');
            setUploading(false);
            setAnalyzing(false);
        }
    };

    const downloadReport = () => {
        if (jobId) {
            window.open(`${API_BASE}/report/${jobId}`, '_blank');
        }
    };

    const getRiskColor = (risk: string) => {
        switch (risk?.toLowerCase()) {
            case 'critical': return 'bg-red-600';
            case 'high': return 'bg-orange-500';
            case 'medium': return 'bg-yellow-500';
            case 'low': return 'bg-green-500';
            default: return 'bg-gray-500';
        }
    };

    const resetAnalysis = () => {
        setFiles([]);
        setJobId(null);
        setResult(null);
        setError(null);
        setProgress(0);
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-8">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="text-center mb-8">
                    <h1 className="text-4xl font-bold text-white mb-2">
                        🔍 NLP Evidence Extraction
                    </h1>
                    <p className="text-slate-400">
                        Upload documents for forensic text analysis
                    </p>
                </div>

                {/* Upload Card */}
                <Card className="bg-slate-800/50 border-slate-700 mb-6">
                    <CardHeader>
                        <CardTitle className="text-white flex items-center gap-2">
                            <Upload className="h-5 w-5" />
                            Upload Files
                        </CardTitle>
                        <CardDescription>
                            Supported: PDF, DOCX, CSV, TXT, JSON
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        {/* Drop Zone */}
                        <div
                            onDrop={handleDrop}
                            onDragOver={(e) => e.preventDefault()}
                            className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-blue-500 transition-colors cursor-pointer"
                            onClick={() => document.getElementById('fileInput')?.click()}
                        >
                            <Upload className="h-12 w-12 mx-auto text-slate-500 mb-4" />
                            <p className="text-slate-400 mb-2">
                                Drag & drop files here, or click to browse
                            </p>
                            <p className="text-slate-500 text-sm">
                                Maximum 10 files, 50MB each
                            </p>
                            <input
                                id="fileInput"
                                type="file"
                                multiple
                                accept=".pdf,.docx,.doc,.csv,.txt,.json"
                                onChange={handleFileSelect}
                                className="hidden"
                            />
                        </div>

                        {/* File List */}
                        {files.length > 0 && (
                            <div className="mt-4 space-y-2">
                                {files.map((file, index) => (
                                    <div
                                        key={index}
                                        className="flex items-center justify-between bg-slate-700/50 rounded-lg p-3"
                                    >
                                        <div className="flex items-center gap-3">
                                            <FileText className="h-5 w-5 text-blue-400" />
                                            <span className="text-white">{file.name}</span>
                                            <span className="text-slate-500 text-sm">
                                                {formatFileSize(file.size)}
                                            </span>
                                        </div>
                                        <button
                                            onClick={() => removeFile(index)}
                                            className="text-slate-500 hover:text-red-400"
                                        >
                                            <X className="h-4 w-4" />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Analyze Button */}
                        {files.length > 0 && !result && (
                            <Button
                                onClick={uploadAndAnalyze}
                                disabled={uploading || analyzing}
                                className="w-full mt-4 bg-blue-600 hover:bg-blue-700"
                            >
                                {uploading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Uploading...
                                    </>
                                ) : analyzing ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Analyzing...
                                    </>
                                ) : (
                                    <>
                                        <Upload className="mr-2 h-4 w-4" />
                                        Analyze {files.length} File{files.length > 1 ? 's' : ''}
                                    </>
                                )}
                            </Button>
                        )}

                        {/* Progress Bar */}
                        {(uploading || analyzing) && (
                            <div className="mt-4">
                                <Progress value={progress} className="h-2" />
                                <p className="text-slate-400 text-sm mt-2 text-center">
                                    {uploading ? 'Uploading files...' : 'Running NLP analysis...'}
                                </p>
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Error Alert */}
                {error && (
                    <Alert variant="destructive" className="mb-6">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

                {/* Results Card */}
                {result && result.summary && (
                    <Card className="bg-slate-800/50 border-slate-700">
                        <CardHeader>
                            <CardTitle className="text-white flex items-center gap-2">
                                <CheckCircle className="h-5 w-5 text-green-500" />
                                Analysis Complete
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            {/* Risk Summary */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                                    <p className="text-slate-400 text-sm">Overall Risk</p>
                                    <Badge className={`${getRiskColor(result.summary.overall_risk)} mt-2`}>
                                        {result.summary.overall_risk.toUpperCase()}
                                    </Badge>
                                </div>
                                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                                    <p className="text-slate-400 text-sm">Files Analyzed</p>
                                    <p className="text-2xl font-bold text-white mt-1">
                                        {result.summary.files_analyzed}
                                    </p>
                                </div>
                                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                                    <p className="text-slate-400 text-sm">Evidence Found</p>
                                    <p className="text-2xl font-bold text-white mt-1">
                                        {result.summary.total_evidence}
                                    </p>
                                </div>
                                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                                    <p className="text-slate-400 text-sm">High Risk Files</p>
                                    <p className="text-2xl font-bold text-orange-400 mt-1">
                                        {result.summary.high_risk_files.length}
                                    </p>
                                </div>
                            </div>

                            {/* High Risk Files Warning */}
                            {result.summary.high_risk_files.length > 0 && (
                                <Alert className="mb-6 border-orange-500 bg-orange-500/10">
                                    <AlertTriangle className="h-4 w-4 text-orange-500" />
                                    <AlertTitle className="text-orange-500">High Risk Files Detected</AlertTitle>
                                    <AlertDescription className="text-orange-300">
                                        {result.summary.high_risk_files.join(', ')}
                                    </AlertDescription>
                                </Alert>
                            )}

                            {/* Download Button */}
                            <div className="flex gap-4">
                                <Button
                                    onClick={downloadReport}
                                    className="flex-1 bg-green-600 hover:bg-green-700"
                                >
                                    <Download className="mr-2 h-4 w-4" />
                                    Download PDF Report
                                </Button>
                                <Button
                                    onClick={resetAnalysis}
                                    variant="outline"
                                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                                >
                                    New Analysis
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                )}
            </div>
        </div>
    );
}
