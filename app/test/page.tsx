"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardFooter,
  CardDescription,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Terminal,
  Lightbulb,
  TriangleAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

type VerdictType = "safe" | "warning" | "danger" | "info";

interface AnalysisResult {
  verdict: string;
  verdictType: VerdictType;
  plainLanguageSummary: string;
  potentialHarm: string;
  actionableAdvice: string;
  receivedHeaders: string[];
  ipHops: string[];
  spfResult: string | null;
  dkimResult: string | null;
  dmarcResult: string | null;
  authenticationResults: string | null;
  fromAddress: string | null;
  replyToAddress: string | null;

  // fields from EmailRep (when input was an email)
  emailRep?: {
    email: string;
    reputation?: string;
    suspicious?: boolean;
    blacklisted?: boolean;
    credentials_leaked?: boolean;
    data_breach?: boolean;
    details?: Record<string, any>;
    references?: number;
  } | null;
}

export default function HomePage() {
  const [emailHeaders, setEmailHeaders] = useState("");
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const looksLikeEmail = (s: string) => {
    const t = s.trim();
    // if its short and contains an @ and no "Received:" lines, treat as an email address
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    if (!emailHeaders.trim()) {
      setError("Please paste email headers **or** an email address to analyze.");
      setLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/analyze-headers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: emailHeaders }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || "Analysis failed");
      } else {
        setAnalysisResult(data as AnalysisResult);
      }
    } catch (err: any) {
      setError(err?.message || "Network error");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictIcon = (type: VerdictType) => {
    switch (type) {
      case "safe":
        return <ShieldCheck className="h-5 w-5 text-green-600" />;
      case "warning":
        return <TriangleAlert className="h-5 w-5 text-orange-500" />;
      case "danger":
        return <XCircle className="h-5 w-5 text-red-600" />;
      case "info":
      default:
        return <Lightbulb className="h-5 w-5 text-blue-500" />;
    }
  };

  return (
    <div className="container mx-auto p-4 md:p-8">
      <Card className="max-w-4xl mx-auto shadow-lg border-t-4 border-blue-500">
        <CardHeader className="text-center">
          <CardTitle className="text-4xl font-extrabold text-blue-700">
            Simple Email / Header Analyzer
          </CardTitle>
          <CardDescription className="mt-2 text-lg text-gray-600">
            Paste raw email headers <strong>or</strong> just an email address.
            (Example address: <code>bill@microsoft.com</code>)
          </CardDescription>
        </CardHeader>

        <CardContent>
          <div className="mb-6">
            <Textarea
              placeholder="Paste raw email headers OR paste a single email address like user@example.com"
              rows={8}
              value={emailHeaders}
              onChange={(e) => setEmailHeaders(e.target.value)}
              className="resize-y text-sm font-mono"
            />
          </div>

          {error && (
            <Alert variant="destructive" className="mb-4">
              <Terminal className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="flex justify-center mb-8">
            <Button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-8 py-3 text-lg bg-blue-600 hover:bg-blue-700"
            >
              {loading ? "Analyzing..." : "Analyze"}
            </Button>
          </div>

          {analysisResult && (
            <div className="mt-8 space-y-6">
              <Card className={`border-l-8 ${analysisResult.verdictType === 'danger' ? 'border-red-500 bg-red-50' : analysisResult.verdictType === 'warning' ? 'border-orange-500 bg-orange-50' : analysisResult.verdictType === 'safe' ? 'border-green-500 bg-green-50' : 'border-blue-500 bg-blue-50'}`}>
                <CardHeader>
                  <div className="flex items-center gap-3">
                    {getVerdictIcon(analysisResult.verdictType)}
                    <h3 className="text-xl font-bold">{analysisResult.verdict}</h3>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="font-medium">Summary</p>
                  <p className="mb-2">{analysisResult.plainLanguageSummary}</p>
                  <p className="font-medium">Potential Harm</p>
                  <p className="mb-2">{analysisResult.potentialHarm}</p>
                  <p className="font-medium">What you should do</p>
                  <p>{analysisResult.actionableAdvice}</p>
                </CardContent>
              </Card>

              {/* If we have EmailRep results, show them */}
              {analysisResult.emailRep ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Email Reputation (EmailRep.io)</CardTitle>
                    <CardDescription>
                      Real enrichment from a free reputation API.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableBody>
                        <TableRow>
                          <TableCell className="font-medium">Email</TableCell>
                          <TableCell>{analysisResult.emailRep.email}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">Reputation</TableCell>
                          <TableCell>{analysisResult.emailRep.reputation?.toString() ?? "N/A"}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">Suspicious</TableCell>
                          <TableCell>{analysisResult.emailRep.suspicious ? "Yes" : "No"}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">Credentials leaked</TableCell>
                          <TableCell>{analysisResult.emailRep.credentials_leaked ? "Yes" : "No"}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">In data breaches</TableCell>
                          <TableCell>{analysisResult.emailRep.data_breach ? "Yes" : "No"}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">Blacklisted</TableCell>
                          <TableCell>{analysisResult.emailRep.blacklisted ? "Yes" : "No"}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell className="font-medium">References</TableCell>
                          <TableCell>{analysisResult.emailRep.references ?? "N/A"}</TableCell>
                        </TableRow>
                      </TableBody>
                    </Table>
                    <div className="mt-3 text-sm text-gray-600">
                      Tip: EmailRep aggregates many signals (OSINT, breach databases, blacklists). If it flags an address as “suspicious” or shows credentials leaked, treat it carefully. (See source: EmailRep.) 
                    </div>
                  </CardContent>
                </Card>
              ) : null}

              {/* Technical Header Details (if present) */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Technical Authentication Details</CardTitle>
                  <CardDescription>SPF / DKIM / DMARC and hops extracted from headers (if provided).</CardDescription>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableBody>
                      <TableRow>
                        <TableCell className="font-medium">From</TableCell>
                        <TableCell>{analysisResult.fromAddress ?? "N/A"}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">Reply-To</TableCell>
                        <TableCell>{analysisResult.replyToAddress ?? "N/A"}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">SPF</TableCell>
                        <TableCell>{analysisResult.spfResult ?? "N/A"}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">DKIM</TableCell>
                        <TableCell>{analysisResult.dkimResult ?? "N/A"}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">DMARC</TableCell>
                        <TableCell>{analysisResult.dmarcResult ?? "N/A"}</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>

                  <div className="mt-4">
                    <h4 className="font-medium">Hops (IPs)</h4>
                    {analysisResult.ipHops.length > 0 ? (
                      <ul className="list-disc ml-5">
                        {analysisResult.ipHops.map((ip) => (
                          <li key={ip} className="font-mono">{ip}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-500">No IPs extracted.</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </CardContent>

        <CardFooter className="text-sm text-gray-500 justify-center p-6">
          <p>
            This tool uses a free public reputation API (EmailRep.io) for email lookups and local header parsing for header inputs. It is designed to be
            conservative — if anything looks off, it will flag it so you stay safe.
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
