"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal } from "lucide-react";
import { AnimatedThemeToggler } from "@/components/animated-theme-toggler";

interface AnalysisResult {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
    timeout: number;
}

interface AnalysisData {
    id: string;
    link: string;
    attributes: {
        stats: AnalysisResult;
        status: string;
        date: number;
    };
}

export default function Home() {
    const [url, setUrl] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<AnalysisData | null>(null);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!url) {
            setError("Please enter a URL.");
            return;
        }

        setLoading(true);
        setResult(null);
        setError(null);

        try {
            const submitResponse = await fetch("/api/scan-url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url }),
            });

            if (!submitResponse.ok) {
                const errorData = await submitResponse.json();
                throw new Error(errorData.message || "Failed to submit URL for analysis.");
            }

            const submitData = await submitResponse.json();
            const urlHash = submitData.urlHash;
            const needsPoll = submitData.needsPoll;

            let analysisResult: AnalysisData | null = null;

            if (!needsPoll) {
                // Immediate result from cache/existing recent scan
                const existingAnalysis = submitData.analysis;
                analysisResult = {
                    id: existingAnalysis.id,
                    attributes: existingAnalysis.attributes,
                    link: `https://www.virustotal.com/gui/url/${urlHash}/detection`,
                };
            } else {
                const analysisId = submitData.data.id;

                let attempts = 0;
                const maxAttempts = 15; // Increased attempts for potentially longer analysis times
                const pollInterval = 3000;

                while (attempts < maxAttempts) {
                    const reportResponse = await fetch(`/api/get-report?analysisId=${analysisId}`);
                    if (!reportResponse.ok) {
                        const errorData = await reportResponse.json();
                        throw new Error(errorData.message || "Failed to retrieve analysis report.");
                    }
                    const reportData = await reportResponse.json();

                    if (reportData.data && reportData.data.attributes.status === "completed") {
                        analysisResult = {
                            id: reportData.data.id,
                            attributes: reportData.data.attributes,
                            link: `https://www.virustotal.com/gui/url/${urlHash}/detection`,
                        };
                        break;
                    }

                    attempts++;
                    await new Promise((resolve) => setTimeout(resolve, pollInterval));
                }
            }

            if (analysisResult) {
                setResult(analysisResult);
            } else {
                setError("Analysis timed out or could not be completed after several attempts. Please try again later.");
            }
        } catch (err: any) {
            setError(err.message || "An unexpected error occurred.");
        } finally {
            setLoading(false);
        }
    };

    // --- New function to interpret the results ---
    const interpretResults = (stats: AnalysisResult) => {
        const totalScans = stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;
        const maliciousPercentage = (stats.malicious / totalScans) * 100;
        const suspiciousPercentage = (stats.suspicious / totalScans) * 100;

        let summary = "";
        let recommendation = "";
        let impact = "";
        let variant = "default"; // For shadcn Alert component styling

        if (stats.malicious > 0) {
            summary = `**HIGH RISK - Malicious URL detected!** ${stats.malicious} security vendors flagged this URL as malicious.`;
            recommendation = "Absolutely DO NOT visit this URL. It is highly dangerous.";
            impact = "Visiting this URL could lead to malware infection, phishing attempts (stealing your login credentials, financial information), or other severe security breaches. Your personal data is at extreme risk.";
            variant = "destructive";
        } else if (stats.suspicious > 0) {
            summary = `**MODERATE RISK - Suspicious activity detected!** ${stats.suspicious} security vendors flagged this URL as suspicious.`;
            recommendation = "Proceed with extreme caution, or preferably, avoid visiting this URL. It may be a developing threat or pose privacy risks.";
            impact = "This URL might lead to phishing attempts, unwanted software installation, or privacy invasion (collecting browsing data, IP address). While not outright malicious yet, it could evolve or be used for targeted attacks.";
            variant = "warning"; // Assuming you have a 'warning' variant or use destructive for similar effect
        } else if (stats.undetected > 0 && stats.harmless === 0) {
            summary = `**UNCERTAIN RISK - Undetected by most vendors.** ${stats.undetected} vendors did not categorize this URL.`;
            recommendation = "Exercise caution. Without a clear 'harmless' rating, there's an inherent uncertainty. It might be a very new URL not yet analyzed, or one designed to evade detection.";
            impact = "Potential risks are unknown. It could be harmless, but also a new, unflagged threat. Proceeding might expose you to novel phishing, malware, or data collection schemes.";
            variant = "warning";
        } else if (stats.harmless > 0 && stats.malicious === 0 && stats.suspicious === 0) {
            summary = `**LOW RISK - Likely Safe.** ${stats.harmless} security vendors found no malicious content.`;
            recommendation = "This URL appears to be safe based on current scans. You can likely visit it without immediate concerns.";
            impact = "Based on current analysis, there is no immediate indication of malicious intent or data theft. However, no scan is 100% foolproof; always be vigilant.";
            variant = "success"; // Assuming you have a 'success' variant or use default for similar effect
        } else {
            summary = "**UNCERTAIN - No clear verdict.** The analysis results are inconclusive or unique.";
            recommendation = "Exercise caution. The URL might be new, or the scanning services couldn't provide a definitive answer.";
            impact = "The exact risks are unclear. It's best to avoid if unsure, or only visit if you completely trust the source and understand potential unknown risks.";
            variant = "default";
        }

        return { summary, recommendation, impact, variant };
    };

    const currentInterpretation = result ? interpretResults(result.attributes.stats) : null;

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
            <Card className="w-full max-w-3xl shadow-xl border-gray-200">
                <CardHeader className="bg-white/70 backdrop-blur-sm p-6 rounded-t-lg">
                    <CardTitle className="text-4xl font-extrabold text-center text-gray-900 leading-tight">
                        Phishing URL Guardian
                    </CardTitle>
                    <CardDescription className="mt-2 text-lg text-center text-gray-600">
                        Paste a URL to instantly understand its safety and potential risks.
                    </CardDescription>
                </CardHeader>
                <CardContent className="p-6">
                    <form onSubmit={handleSubmit} className="flex flex-col space-y-5">
                        <Input
                            type="text"
                            placeholder="Paste URL here (e.g., https://malicious.example.com)"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            className="text-lg p-3 border-2 border-blue-300 focus:border-blue-500 transition-colors duration-200"
                        />
                        <Button
                            type="submit"
                            className="w-full text-lg py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                            disabled={loading}
                        >
                            {loading ? "Analyzing URL..." : "Check URL Safety"}
                        </Button>
                    </form>

                    {error && (
                        <Alert variant="destructive" className="mt-6">
                            <Terminal className="h-4 w-4" />
                            <AlertTitle>Error!</AlertTitle>
                            <AlertDescription>{error}</AlertDescription>
                        </Alert>
                    )}

                    {loading && (
                        <div className="mt-6 flex justify-center items-center">
                            <svg className="animate-spin h-8 w-8 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            <p className="ml-3 text-gray-700 text-lg">Scanning URL with multiple engines...</p>
                        </div>
                    )}

                    {result && currentInterpretation && (
                        <div className="mt-8 border-t-2 border-gray-200 pt-6">
                            <h3 className="text-3xl font-bold mb-5 text-center text-gray-800">Safety Analysis Report</h3>

                            {/* Dynamic Alert based on interpretation */}
                            <Alert
                                className={`
                  mb-6 p-5 rounded-lg border-2
                  ${currentInterpretation.variant === 'destructive' ? 'bg-red-50 border-red-400 text-red-800' : ''}
                  ${currentInterpretation.variant === 'warning' ? 'bg-yellow-50 border-yellow-400 text-yellow-800' : ''}
                  ${currentInterpretation.variant === 'success' ? 'bg-green-50 border-green-400 text-green-800' : ''}
                  ${currentInterpretation.variant === 'default' ? 'bg-gray-50 border-gray-400 text-gray-800' : ''}
                `}
                            >
                                <Terminal className={`h-5 w-5 ${currentInterpretation.variant === 'destructive' ? 'text-red-600' : currentInterpretation.variant === 'warning' ? 'text-yellow-600' : currentInterpretation.variant === 'success' ? 'text-green-600' : 'text-gray-600'}`} />
                                <AlertTitle className="text-2xl font-bold mb-2">
                                    {currentInterpretation.summary}
                                </AlertTitle>
                                <AlertDescription className="text-lg leading-relaxed space-y-3">
                                    <p><span className="font-semibold">Recommendation:</span> {currentInterpretation.recommendation}</p>
                                    <p><span className="font-semibold">Potential Impact:</span> {currentInterpretation.impact}</p>
                                    <p className="text-sm mt-4 text-gray-600 italic">
                                        <span className="font-medium">Disclaimer:</span> This analysis is based on data from various security vendors. While comprehensive, new threats emerge constantly. Always exercise caution online.
                                    </p>
                                </AlertDescription>
                            </Alert>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-center mt-6">
                                <div className="bg-green-100 p-4 rounded-md">
                                    <p className="text-sm text-green-700 font-medium">Harmless Verdicts</p>
                                    <p className="text-3xl font-bold text-green-800 mt-1">{result.attributes.stats.harmless}</p>
                                </div>
                                <div className="bg-red-100 p-4 rounded-md">
                                    <p className="text-sm text-red-700 font-medium">Malicious Verdicts</p>
                                    <p className="text-3xl font-bold text-red-800 mt-1">{result.attributes.stats.malicious}</p>
                                </div>
                                <div className="bg-yellow-100 p-4 rounded-md">
                                    <p className="text-sm text-yellow-700 font-medium">Suspicious Verdicts</p>
                                    <p className="text-3xl font-bold text-yellow-800 mt-1">{result.attributes.stats.suspicious}</p>
                                </div>
                                <div className="bg-blue-100 p-4 rounded-md col-span-full md:col-span-1">
                                    <p className="text-sm text-blue-700 font-medium">Undetected by Vendors</p>
                                    <p className="text-3xl font-bold text-blue-800 mt-1">{result.attributes.stats.undetected}</p>
                                </div>
                                <div className="bg-gray-100 p-4 rounded-md col-span-full md:col-span-2 flex flex-col justify-center">
                                    <p className="text-sm text-gray-700 font-medium">Scan Details</p>
                                    <p className="text-lg font-bold text-gray-800 mt-1">Status: <span className="capitalize">{result.attributes.status}</span></p>
                                    <p className="text-md text-gray-700 mt-1">Analysis Date: {new Date(result.attributes.date * 1000).toLocaleString()}</p>
                                </div>
                            </div>

                            <p className="mt-8 text-md text-gray-700 text-center">
                                For the raw, detailed report from VirusTotal with specific vendor detections, visit:{" "}
                                <a
                                    href={result.link}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-600 hover:underline font-medium"
                                >
                                    View Full VirusTotal Report
                                </a>
                            </p>
                        </div>
                    )}
                </CardContent>
            </Card>
            <AnimatedThemeToggler />
        </div>
    );
}