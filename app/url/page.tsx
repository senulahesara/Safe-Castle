"use client"

import React from 'react'
import { useEffect, useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ClipboardPaste, Link, Loader, Terminal } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Globe, Shield, MapPin, AlertTriangle, ImageIcon, Copy, Share2 } from "lucide-react";
import { toast } from "sonner";
import { Label } from '@/components/ui/label';
import { NavBar } from '@/components/NavBar';

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

interface AdditionalResults {
    isSuspiciousKeywords: boolean;
    openPhish: boolean;
    sslStatus: string;
    ipGeo: { country: string; countryCode: string; regionName: string; city: string } | null;
    isHighRiskGeo: boolean;
    redirectCount: number;
}

function page() {

    const [url, setUrl] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<AnalysisData | null>(null);
    const [additionalResults, setAdditionalResults] = useState<AdditionalResults | null>(null);
    const [riskScore, setRiskScore] = useState<number>(0);
    const [loadingMessage, setLoadingMessage] = useState<string>("");
    const [copiedReport, setCopiedReport] = useState(false);
    const [copiedShare, setCopiedShare] = useState(false);
    const searchParams = useSearchParams();

    // Function to check if a string is a valid URL
    const isValidUrl = (url: string) => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    };

    const submitUrl = async (urlToCheck: string) => {

        if (!urlToCheck) {
            toast.error("URL Required", {
                description: "Please enter or paste a valid URL before starting the analysis.",
            });
            return;
        }

        if (!isValidUrl(urlToCheck)) {
            toast.error("Invalid URL", {
                description: "Hmm... that doesn’t look like a valid link.",
            });
            return;
        }

        const cachedKey = `scan_${urlToCheck}`;
        const cached = localStorage.getItem(cachedKey);
        if (cached) {
            const parsed = JSON.parse(cached);
            setResult(parsed.result);
            setAdditionalResults(parsed.additional);
            calculateRiskScore(parsed.result, parsed.additional);
            return;
        }

        setLoading(true);
        setResult(null);
        setAdditionalResults(null);
        setLoadingMessage("Initiating scan...");

        try {
            // VirusTotal scan (existing logic)
            const submitResponse = await fetch("/api/scan-url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url: urlToCheck }),
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
                const existingAnalysis = submitData.analysis;
                analysisResult = {
                    id: existingAnalysis.id,
                    attributes: existingAnalysis.attributes,
                    link: `https://www.virustotal.com/gui/url/${urlHash}/detection`,
                };
            } else {
                const analysisId = submitData.data.id;

                let attempts = 0;
                const maxAttempts = 15;
                const pollInterval = 3000;

                while (attempts < maxAttempts) {
                    setLoadingMessage(`Polling attempt ${attempts + 1} of ${maxAttempts}...`);
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
                toast.error("Analysis Timed Out", {
                    description: "The scan took too long. Please try again in a moment.",
                });
                return;
            }

            // Additional checks
            const host = new URL(urlToCheck).hostname;

            // Suspicious keywords
            const suspiciousKeywords = ['login', 'secure-update', 'paypal-verification', 'bank', 'account', 'verify'];
            const isSuspiciousKeywords = suspiciousKeywords.some(k => urlToCheck.toLowerCase().includes(k));

            // OpenPhish check (blacklist/phishing)
            let openPhish = false;
            try {
                setLoadingMessage("Checking against OpenPhish...");
                const phishRes = await fetch('https://openphish.com/feed.txt');
                const phishText = await phishRes.text();
                openPhish = phishText.split('\n').some(line => line.trim() === urlToCheck.trim());
            } catch { }

            // SSL/TLS check
            let sslStatus = 'unknown';
            try {
                setLoadingMessage("Checking SSL certificate...");
                const sslRes = await fetch(`https://api.ssllabs.com/api/v3/analyze?host=${host}&fromCache=on&maxAge=24`);
                const sslData = await sslRes.json();
                if (sslData.status === 'READY') {
                    const endpoints = sslData.endpoints;
                    if (endpoints && endpoints.length > 0) {
                        const grade = endpoints[0].grade;
                        if (grade) {
                            sslStatus = `Valid (Grade: ${grade})`;
                            if (['F', 'T'].includes(grade)) sslStatus = 'Invalid';
                        } else {
                            sslStatus = 'Invalid';
                        }
                    }
                } else if (sslData.status === 'ERROR') {
                    sslStatus = 'Error';
                }
            } catch { }

            // IP Geolocation
            let ipGeo = null;
            let isHighRiskGeo = false;
            try {
                setLoadingMessage("Finding server location...");
                const dnsRes = await fetch(`https://dns.google/resolve?name=${host}&type=A`);
                const dnsData = await dnsRes.json();
                const ip = dnsData.Answer ? dnsData.Answer[0].data : null;
                if (ip) {
                    const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city`);
                    const geoData = await geoRes.json();
                    if (geoData.status === 'success') {
                        ipGeo = geoData;
                        const highRiskCountries = ['RU', 'CN', 'IR', 'KP', 'SY'];
                        isHighRiskGeo = highRiskCountries.includes(geoData.countryCode);
                    }
                }
            } catch { }



            // Redirect tracing (basic, detects if at least one redirect)
            let redirectCount = 0;
            try {
                setLoadingMessage("Checking for redirects...");
                const response = await fetch(urlToCheck, { method: 'HEAD', redirect: 'manual' });
                if (response.status >= 300 && response.status < 400) {
                    redirectCount = 1; // At least one redirect detected
                }
            } catch { }

            const addResults: AdditionalResults = {
                isSuspiciousKeywords,
                openPhish,
                sslStatus,
                ipGeo,
                isHighRiskGeo,
                redirectCount,
            };
            setAdditionalResults(addResults);

            // Cache results (offline mode)
            localStorage.setItem(cachedKey, JSON.stringify({ result: analysisResult, additional: addResults }));

            // Calculate risk score
            calculateRiskScore(analysisResult, addResults);
        } catch (err: any) {
            const errorMessage =
                (err && err.message) || "Something went wrong. Please try again.";

            toast.error("Error", {
                description: errorMessage,
            });
        } finally {
            setLoading(false);
            setLoadingMessage("");
        }
    };

    const calculateRiskScore = (res: AnalysisData, add: AdditionalResults) => {
        const stats = res.attributes.stats;
        const totalScans = stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;
        let score = 100;

        if (stats.malicious > 0) score -= 50;
        if (stats.suspicious > 0) score -= 20;
        if (stats.timeout > 0 || stats.undetected > totalScans / 2) score -= 10;
        if (add.isSuspiciousKeywords) score -= 10;
        if (add.openPhish) score -= 40;
        if (add.sslStatus.includes('Invalid') || add.sslStatus === 'Error') score -= 30;
        if (add.isHighRiskGeo) score -= 20;
        if (add.redirectCount > 2) score -= 15;

        score = Math.max(0, score);
        setRiskScore(score);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        await submitUrl(url);
    };

    const interpretResults = (stats: AnalysisResult) => {
        let summary = "";
        let recommendation = "";
        let impact = "";
        let variant = "default";

        if (stats.malicious > 0) {
            summary = `High Risk: ${stats.malicious} checks say it's bad.`;
            recommendation = "Do not visit this site. It's dangerous.";
            impact = "It could harm your device or steal your info.";
            variant = "destructive";
        } else if (stats.suspicious > 0) {
            summary = `Medium Risk: ${stats.suspicious} checks say it's suspicious.`;
            recommendation = "Be careful or avoid it.";
            impact = "Might try to trick you or install bad software.";
            variant = "warning";
        } else if (stats.undetected > 0 && stats.harmless === 0) {
            summary = "Unsure: Most checks didn't find anything.";
            recommendation = "Be careful. It might be new and unknown.";
            impact = "Could be safe or a hidden threat.";
            variant = "warning";
        } else if (stats.harmless > 0 && stats.malicious === 0 && stats.suspicious === 0) {
            summary = `Low Risk: ${stats.harmless} checks say it's safe.`;
            recommendation = "Looks okay, but stay alert.";
            impact = "No big problems found.";
            variant = "success";
        } else {
            summary = "Unsure: Results are not clear.";
            recommendation = "Avoid if you can.";
            impact = "Risks are unknown.";
            variant = "default";
        }

        return { summary, recommendation, impact, variant };
    };

    const currentInterpretation = result ? interpretResults(result.attributes.stats) : null;

    const handleCopyReport = () => {
        navigator.clipboard.writeText(JSON.stringify({ result, additional: additionalResults }));
        setCopiedReport(true);
        setTimeout(() => setCopiedReport(false), 2000);
    };

    const handleCopyShare = () => {
        navigator.clipboard.writeText(`${window.location.origin}?url=${encodeURIComponent(url)}`);
        setCopiedShare(true);
        setTimeout(() => setCopiedShare(false), 2000);
    };

    // Handle paste from clipboard
    const handlePaste = async () => {
        try {
            const text = await navigator.clipboard.readText();
            setUrl(text);
        } catch (err) {
            toast.error("Oops!", {
                description: "Couldn't read from your clipboard. Please try again.",
            });
        }
    };

    useEffect(() => {
        const urlFromQuery = searchParams.get("url") || "";
        if (urlFromQuery) {
            setUrl(urlFromQuery);
            submitUrl(urlFromQuery);
        }
    }, [searchParams]);


    return (
        <>
            <NavBar />
            <div className="min-h-screen dark:bg-black bg-white py-12 px-6">
                <div className="max-w-7xl mx-auto">
                    <div className="mb-8">
                        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight dark:text-gray-100 text-black">
                            Phishing URL Guardian
                        </h1>
                        <p className="mt-2 text-gray-400 max-w-2xl">
                            Instantly analyze any URL for safety. Checks domain reputation, SSL/TLS validity, IP geolocation, blacklist status, redirects, and suspicious keywords. offline caching, and a combined risk score (0-100) with real-time updates.
                        </p>
                    </div>

                    <Card className="shadow-2xl overflow-hidden dark:bg-black bg-white">
                        <div className="md:flex flex-col md:flex-row">
                            {/* RIGHT: INPUT + ACTIONS (desktop right column; mobile stacked above details) */}
                            <div className="md:w-1/2 p-6 md:p-10 dark:bg-black bg-white order-first md:order-none"> {/* Added order-first for mobile */}
                                <div className="max-w-xl mx-auto">
                                    <div className="w-full">
                                        <form onSubmit={handleSubmit} className="flex flex-col">
                                            <Label >Enter URL</Label>
                                            <div className='mt-2'>
                                                <Input
                                                    type="text"
                                                    placeholder="Enter URL here... (e.g., https://example.com)"
                                                    value={url}
                                                    onChange={(e) => setUrl(e.target.value)}
                                                />
                                            </div>
                                            <div className="mt-6 flex flex-col sm:flex-row gap-3">
                                                <Button
                                                    type="submit"
                                                    className="cursor-pointer flex-1"
                                                    disabled={loading}
                                                >
                                                    {loading ? "Checking..." : <> <Link /> Check URL</>}
                                                </Button>

                                                <Button type="button" variant="secondary" className="w-full sm:w-36" onClick={handlePaste}>
                                                    <ClipboardPaste /> Paste URL
                                                </Button>
                                            </div>
                                        </form>

                                        {loading && (
                                            <div className="mt-4 flex justify-center items-center">
                                                <Loader className='animate-spin h-6 w-6' />
                                                <p className="ml-2 text-gray-300 text-base">{loadingMessage || "Scanning..."}</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* LEFT: DETAILS (desktop: visible as left column, mobile: below input) */}
                            <div className="md:w-1/2 dark:bg-black bg-white p-6 md:p-8 border-t md:border-t-0 md:border-l md:border-gray-700 md:order-last"> {/* Added md:order-last for mobile */}
                                <div className="w-full">
                                    <div className="space-y-4">
                                        <h3 className="text-xl font-bold text-center text-gray-100">Report</h3>

                                        {/* Risk Score */}
                                        <div>
                                            <div className="flex justify-between text-sm mb-1">
                                                <span>Safe Score</span>
                                                <span>{riskScore}/100</span>
                                            </div>
                                            <Progress value={riskScore} className="w-full" />
                                        </div>

                                        {/* Alert */}
                                        {currentInterpretation ? (
                                            <Alert
                                                variant={currentInterpretation.variant as any}
                                                className={`p-3 rounded-lg border text-sm ${currentInterpretation.variant === 'destructive' ? 'bg-red-900/50 border-red-600 text-red-200' : ''} ${currentInterpretation.variant === 'warning' ? 'bg-yellow-900/50 border-yellow-600 text-yellow-200' : ''} ${currentInterpretation.variant === 'success' ? 'bg-green-900/50 border-green-600 text-green-200' : ''} ${currentInterpretation.variant === 'default' ? 'bg-gray-900/50 border-gray-600 text-gray-200' : ''}`}
                                            >
                                                <Terminal className={`h-4 w-4 ${currentInterpretation.variant === 'destructive' ? 'text-red-400' : currentInterpretation.variant === 'warning' ? 'text-yellow-400' : currentInterpretation.variant === 'success' ? 'text-green-400' : 'text-gray-400'}`} />
                                                <AlertTitle className="text-base font-bold mb-1">
                                                    {currentInterpretation.summary}
                                                </AlertTitle>
                                                <AlertDescription className="space-y-1">
                                                    <p><span className="font-semibold">Advice:</span> {currentInterpretation.recommendation}</p>
                                                    <p><span className="font-semibold">Why:</span> {currentInterpretation.impact}</p>
                                                    <p className="text-xs mt-2 text-gray-400 italic">
                                                        Note: Always be careful online. New dangers appear often.
                                                    </p>
                                                </AlertDescription>
                                            </Alert>
                                        ) : (
                                            <Alert
                                                variant="default"
                                                className="p-3 rounded-lg border text-sm bg-black border-accent text-gray-200"
                                            >
                                                <Terminal className="h-4 w-4 text-gray-400" />
                                                <AlertTitle className="text-base font-bold mb-1">
                                                    No Analysis Yet
                                                </AlertTitle>
                                                <AlertDescription className="space-y-1">
                                                    <p>Enter a URL and check to see the report.</p>
                                                </AlertDescription>
                                            </Alert>
                                        )}

                                        {/* VirusTotal Results */}
                                        <div className="space-y-2 text-sm">
                                            <h4 className="font-semibold text-gray-100">VirusTotal Checks</h4>
                                            <div className="grid grid-cols-2 gap-2">
                                                <div className="bg-accent p-2 rounded">
                                                    <p className="text-green-400">Safe</p>
                                                    <p className="text-xl font-bold text-green-300">{result ? result.attributes.stats.harmless : '-'}</p>
                                                </div>
                                                <div className="bg-accent p-2 rounded">
                                                    <p className="text-red-400">Bad</p>
                                                    <p className="text-xl font-bold text-red-300">{result ? result.attributes.stats.malicious : '-'}</p>
                                                </div>
                                                <div className="bg-accent p-2 rounded">
                                                    <p className="text-yellow-400">Suspicious</p>
                                                    <p className="text-xl font-bold text-yellow-300">{result ? result.attributes.stats.suspicious : '-'}</p>
                                                </div>
                                                <div className="bg-accent p-2 rounded">
                                                    <p className="text-blue-400">Not Checked</p>
                                                    <p className="text-xl font-bold text-blue-300">{result ? result.attributes.stats.undetected : '-'}</p>
                                                </div>
                                            </div>
                                            <p className='text-gray-300'>Status: {result ? result.attributes.status : '-'}</p>
                                            <p className='text-gray-300'>Date: {result ? new Date(result.attributes.date * 1000).toLocaleString() : '-'}</p>
                                        </div>

                                        {/* Additional Checks */}
                                        <div className="space-y-2 text-sm">
                                            <Label>Other Checks</Label>
                                            <div className="flex items-center text-gray-300">
                                                <p>Suspicious Words: {additionalResults ? <Badge variant={additionalResults.isSuspiciousKeywords ? "destructive" : "secondary"}>{additionalResults.isSuspiciousKeywords ? "Yes" : "No"}</Badge> : '-'}</p>
                                            </div>
                                            <div className="flex items-center text-gray-300">
                                                <p>Phishing List: {additionalResults ? <Badge variant={additionalResults.openPhish ? "destructive" : "secondary"}>{additionalResults.openPhish ? "Yes" : "No"}</Badge> : '-'}</p>
                                            </div>
                                            <div className="flex items-center text-gray-300">
                                                <p>SSL Cert: {additionalResults ? <Badge variant={additionalResults.sslStatus.includes('Valid') ? "secondary" : "destructive"}>{additionalResults.sslStatus}</Badge> : '-'}</p>
                                            </div>
                                            <div className="flex items-center text-gray-300">
                                                <p>Location: {additionalResults?.ipGeo ? `${additionalResults.ipGeo.city}, ${additionalResults.ipGeo.country}` : "-"}</p>
                                            </div>
                                            <div className="flex items-center text-gray-300">
                                                <p>High Risk Area: {additionalResults ? <Badge variant={additionalResults.isHighRiskGeo ? "destructive" : "secondary"}>{additionalResults.isHighRiskGeo ? "Yes" : "No"}</Badge> : '-'}</p>
                                            </div>
                                            <div className="flex items-center text-gray-300">
                                                <p>Redirects: {additionalResults ? <Badge variant={additionalResults.redirectCount > 2 ? "destructive" : "secondary"}>{additionalResults.redirectCount}</Badge> : '-'}</p>
                                            </div>
                                        </div>

                                        {/* Buttons */}
                                        {result && (
                                            <div className="flex justify-center space-x-3 mt-4">
                                                <Button
                                                    onClick={handleCopyReport}
                                                    className="flex items-center text-sm py-1"
                                                >
                                                    <Copy className="h-3 w-3 mr-1" /> {copiedReport ? "Copied!" : "Copy Report"}
                                                </Button>
                                                <Button
                                                    onClick={handleCopyShare}
                                                    className="flex items-center text-sm py-1"
                                                >
                                                    <Share2 className="h-3 w-3 mr-1" /> {copiedShare ? "Copied!" : "Copy Share Link"}
                                                </Button>
                                            </div>
                                        )}

                                        {result && (
                                            <p className="mt-4 text-sm text-gray-400 text-center">
                                                See full report: <a href={result.link} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">VirusTotal</a>
                                            </p>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Card>
                </div>
            </div>
        </>
    )
}

export default page