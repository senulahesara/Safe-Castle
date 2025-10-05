"use client"

import { NavBar } from '@/components/NavBar'
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Award, CheckCircle, ClipboardPaste, Clock, Globe, Loader, ShieldCheck, XCircle } from 'lucide-react';
import React, { useState } from 'react'
import { toast } from 'sonner';

interface CertificateDetail {
    domain: string;
    validity: string;
    issuer: string;
    commonName: string;
    expiryDate: string;
    startDate: string;
    serialNumber: string;
    signatureAlgorithm: string;
    publicKeyAlgorithm: string;
    publicKeySize: number;
    keyUsages: string[];
    extendedKeyUsages: string[];
    ciphers: { name: string; strength: string; forwardSecrecy: boolean }[];
    hsts: boolean;
    tlsVersions: string[];
    subjectAltNames: string[];
    isSelfSigned: null;
    isExpired: boolean;
    dnsStatus: string;
    certificateChain: {
        commonName: string;
        issuer: string;
        validity: string;
        serialNumber: string;
        publicKeySize?: number;
    }[];
    ocspStapling: {
        enabled: boolean;
        responseStatus?: string;
        nextUpdate?: string;
    };
    ctStatus: {
        enabled: boolean;
        logsCount: number;
        logs?: { name: string; status: string; timestamp: string }[];
    };
    revocationUris: {
        crl: string[];
        ocsp: string[];
    };
    caaRecords: string[];
    negotiatedProtocol: string;
    negotiatedCipher: string;
    grade: string;
}

const defaultCert: CertificateDetail = {
    domain: 'No domain checked yet',
    validity: 'N/A',
    issuer: 'N/A',
    commonName: 'N/A',
    expiryDate: '',
    startDate: '',
    serialNumber: 'N/A',
    signatureAlgorithm: 'N/A',
    publicKeyAlgorithm: 'N/A',
    publicKeySize: 0,
    keyUsages: [],
    extendedKeyUsages: [],
    ciphers: [],
    hsts: false,
    tlsVersions: [],
    subjectAltNames: [],
    isSelfSigned: null,
    isExpired: false,
    dnsStatus: 'N/A',
    certificateChain: [],
    ocspStapling: { enabled: false },
    ctStatus: { enabled: false, logsCount: 0 },
    revocationUris: { crl: [], ocsp: [] },
    caaRecords: [],
    negotiatedProtocol: 'N/A',
    negotiatedCipher: 'N/A',
    grade: 'N/A',
};

export default function Page() {   // ✅ Changed to uppercase "Page"

    const [domain, setDomain] = useState<string>('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [certDetails, setCertDetails] = useState<CertificateDetail | null>(null);

    // Handle paste from clipboard
    const handlePaste = async () => {
        try {
            const text = await navigator.clipboard.readText();
            setDomain(text);
        } catch {
            // ✅ removed unused "err"
            toast.error("Oops!", {
                description: "Couldn't read from your clipboard. Please try again.",
            });
        }
    };

    // Function to check if a string is a valid URL
    const isValidUrl = (url: string) => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!domain) {
            toast.error("URL Required", {
                description: "Please enter or paste a valid URL before starting the analysis.",
            });
            return;
        }

        if (!isValidUrl(domain)) {
            toast.error("Invalid URL", {
                description: "Hmm... that doesn’t look like a valid link.",
            });
            return;
        }

        setLoading(true);
        setError(null);
        setCertDetails(null);

        try {
            const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
            const response = await fetch(`/api/check-ssl?domain=${encodeURIComponent(cleanDomain)}`);

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.details || errorData.error || 'Failed to fetch SSL details');
            }

            const data: CertificateDetail = await response.json();
            setCertDetails(data);
        } catch (err) {
            setError((err as Error).message);
        } finally {
            setLoading(false);
        }
    };

    const displayDetails = certDetails || defaultCert;

    return (
        <>
            <NavBar />
            <div className="min-h-screen dark:bg-black bg-white py-12 px-6">
                <div className="max-w-7xl mx-auto">
                    <div className="mb-8">
                        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight dark:text-gray-100 text-black">
                            SSL / TLS Checker
                        </h1>
                        <p className="mt-2 text-gray-400 max-w-2xl">
                            This SSL/TLS Checker lets you instantly analyze any website’s security certificate, showing details like validity, issuer, chain, revocation, supported protocols, ciphers, and overall grade to quickly assess site safety.
                        </p>
                    </div>

                    <Card className="shadow-2xl overflow-hidden dark:bg-black bg-white">
                        <div className="md:flex flex-col md:flex-row">
                            {/* RIGHT: INPUT + ACTIONS (desktop right column; mobile stacked above details) */}
                            <div className="md:w-1/2 p-6 md:p-10 dark:bg-black bg-white order-first md:order-none"> {/* Added order-first for mobile */}
                                <form onSubmit={handleSubmit} className="space-y-4">
                                    <div className="grid w-full items-center gap-1.5">
                                        <Label htmlFor="domain">Domain Name</Label>
                                        <Input
                                            type="text"
                                            id="domain"
                                            placeholder="example.com"
                                            value={domain}
                                            onChange={(e) => setDomain(e.target.value)}
                                        />
                                    </div>

                                    <div className="mt-6 flex flex-col sm:flex-row gap-3">
                                        <Button
                                            type="submit"
                                            className="cursor-pointer flex-1"
                                            disabled={loading}
                                        >
                                            {loading ? (
                                                <>
                                                    <Loader className="mr-2 h-4 w-4 animate-spin" /> Checking...
                                                </>
                                            ) : (
                                                <>
                                                    <ShieldCheck className="mr-2 h-4 w-4" /> Check SSL
                                                </>
                                            )}
                                        </Button>

                                        <Button type="button" variant="secondary" className="w-full sm:w-36" onClick={handlePaste}>
                                            <ClipboardPaste /> Paste URL
                                        </Button>
                                    </div>

                                </form>

                                {error && (
                                    toast.error("Error", {
                                        description: error,
                                    })
                                )}

                            </div>

                            {/* LEFT: DETAILS (desktop: visible as left column, mobile: below input) */}
                            <div className="md:w-1/2 dark:bg-black bg-white p-6 md:p-8 border-t md:border-t-0 md:border-l md:border-gray-700 md:order-last"> {/* Added md:order-last for mobile */}
                                <div className="space-y-6">

                                    <h3 className="text-xl font-semibold flex items-center">
                                        <ShieldCheck className="mr-2 h-5 w-5 text-green-500" /> Certificate Details for {displayDetails.domain}
                                    </h3>

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Validity</p>
                                            <p className={`flex items-center ${displayDetails.validity === 'Valid' ? 'text-green-500' : 'text-red-500'}`}>
                                                {displayDetails.validity === 'Valid' ? <CheckCircle className="h-4 w-4 mr-1" /> : <XCircle className="h-4 w-4 mr-1" />}
                                                {displayDetails.validity || 'N/A'}
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Issuer</p>
                                            <p>{displayDetails.issuer || 'N/A'}</p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Expiry Date</p>
                                            <p className="flex items-center">
                                                <Clock className="h-4 w-4 mr-1" />
                                                {displayDetails.expiryDate ? new Date(displayDetails.expiryDate).toLocaleDateString() : 'N/A'}
                                                {displayDetails.isExpired && <span className="ml-2 text-red-500 font-bold">(Expired!)</span>}
                                            </p>
                                        </div>
                                        {displayDetails.startDate && (
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground">Valid From</p>
                                                <p>{displayDetails.startDate ? new Date(displayDetails.startDate).toLocaleDateString() : 'N/A'}</p>
                                            </div>
                                        )}
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Serial Number</p>
                                            <p className="break-all text-sm">{displayDetails.serialNumber || 'N/A'}</p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">HSTS Enabled</p>
                                            <p className={`flex items-center ${displayDetails.hsts ? 'text-green-500' : 'text-red-500'}`}>
                                                {displayDetails.hsts ? <CheckCircle className="h-4 w-4 mr-1" /> : <XCircle className="h-4 w-4 mr-1" />}
                                                {displayDetails.hsts ? 'Yes' : 'No'}
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Self-Signed</p>
                                            {displayDetails.isSelfSigned === null ? (
                                                <p className="text-sm">N/A</p>
                                            ) : (
                                                <p className={`flex items-center ${displayDetails.isSelfSigned ? 'text-red-500' : 'text-green-500'}`}>
                                                    {displayDetails.isSelfSigned ? (
                                                        <>
                                                            <XCircle className="h-4 w-4 mr-1" /> Yes
                                                        </>
                                                    ) : (
                                                        <>
                                                            <CheckCircle className="h-4 w-4 mr-1" /> No
                                                        </>
                                                    )}
                                                </p>
                                            )}
                                        </div>

                                    </div>

                                    {displayDetails.subjectAltNames.length > 0 && (
                                        <>
                                            <Separator />
                                            <h4 className="text-lg font-semibold">Subject Alternative Names (SANs)</h4>
                                            <ul className="list-disc pl-5">
                                                {displayDetails.subjectAltNames.map((san, index) => (
                                                    <li key={index}>{san}</li>
                                                ))}
                                            </ul>
                                        </>
                                    )}

                                    <Separator />

                                    <h4 className="text-lg font-semibold">Certificate Chain</h4>
                                    {displayDetails.certificateChain.length === 0 ? (
                                        <p className="text-sm text-muted-foreground">Not Available</p>
                                    ) : (
                                        <ol className="list-decimal pl-5 space-y-2">
                                            {displayDetails.certificateChain.map((cert, index) => (
                                                <li key={index}>
                                                    <p className="font-medium">{cert.commonName || 'Unknown'}</p>
                                                    <p className="text-sm text-muted-foreground">Issued by: {cert.issuer || 'Unknown'}</p>
                                                    <p className="text-sm text-muted-foreground">Status: {cert.validity || 'Unknown'}</p>
                                                </li>
                                            ))}
                                        </ol>
                                    )}

                                    <Separator />
                                    <h4 className="text-lg font-semibold">Public Key & Signature</h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Signature Algorithm</p>
                                            <p>{displayDetails.signatureAlgorithm || 'N/A'}</p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Public Key</p>
                                            <p>{displayDetails.publicKeyAlgorithm ? `${displayDetails.publicKeyAlgorithm} (${displayDetails.publicKeySize} bits)` : 'N/A'}</p>
                                        </div>
                                    </div>

                                    {displayDetails.tlsVersions.length > 0 && (
                                        <>
                                            <Separator />
                                            <h4 className="text-lg font-semibold">TLS Versions Supported</h4>
                                            <ul className="list-disc pl-5">
                                                {displayDetails.tlsVersions.map((version, index) => (
                                                    <li key={index}>{version}</li>
                                                ))}
                                            </ul>
                                        </>
                                    )}

                                    {displayDetails.ciphers.length > 0 && (
                                        <>
                                            <Separator />
                                            <h4 className="text-lg font-semibold">Cipher Suites</h4>
                                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                                {displayDetails.ciphers.map((cipher, index) => (
                                                    <div key={index} className={`p-2 rounded-md ${cipher.strength === 'Strong' ? 'bg-green-900/20' : 'bg-red-900/20'}`}>
                                                        <p className="text-sm font-medium">{cipher.name}</p>
                                                        <p className={`text-xs ${cipher.strength === 'Strong' ? 'text-green-400' : 'text-red-400'}`}>
                                                            Strength: {cipher.strength}
                                                        </p>
                                                    </div>
                                                ))}
                                            </div>
                                        </>
                                    )}

                                    {displayDetails.keyUsages.length > 0 && (
                                        <>
                                            <Separator />
                                            <h4 className="text-lg font-semibold">Key Usages</h4>
                                            <ul className="list-disc pl-5">
                                                {displayDetails.keyUsages.map((usage, index) => <li key={index}>{usage}</li>)}
                                            </ul>
                                        </>
                                    )}

                                    {displayDetails.extendedKeyUsages && displayDetails.extendedKeyUsages.length > 0 && (
                                        <>
                                            <h4 className="text-lg font-semibold mt-4">Extended Key Usages</h4>
                                            <ul className="list-disc pl-5">
                                                {displayDetails.extendedKeyUsages.map((usage, index) => <li key={index}>{usage}</li>)}
                                            </ul>
                                        </>
                                    )}

                                    <Separator />
                                    <h4 className="text-lg font-semibold">DNS Status</h4>
                                    <p className="flex items-center">
                                        <Globe className="h-4 w-4 mr-1" />
                                        {displayDetails.dnsStatus || 'N/A'}
                                    </p>

                                    <Separator />
                                    <h4 className="text-lg font-semibold">OCSP Stapling</h4>
                                    <div className="space-y-2">
                                        <p className={`flex items-center ${displayDetails.ocspStapling.enabled ? 'text-green-500' : 'text-red-500'}`}>
                                            {displayDetails.ocspStapling.enabled ? <CheckCircle className="h-4 w-4 mr-1" /> : <XCircle className="h-4 w-4 mr-1" />}
                                            Enabled: {displayDetails.ocspStapling.enabled ? 'Yes' : 'No'}
                                        </p>
                                        {displayDetails.ocspStapling.enabled && (
                                            <>
                                                <p className="text-sm text-muted-foreground">Response Status: {displayDetails.ocspStapling.responseStatus || 'N/A'}</p>
                                                <p className="text-sm text-muted-foreground">Next Update: {displayDetails.ocspStapling.nextUpdate || 'N/A'}</p>
                                            </>
                                        )}
                                    </div>

                                    <Separator />
                                    <h4 className="text-lg font-semibold">Certificate Transparency (CT)</h4>
                                    <div className="space-y-2">
                                        <p className={`flex items-center ${displayDetails.ctStatus.enabled ? 'text-green-500' : 'text-red-500'}`}>
                                            {displayDetails.ctStatus.enabled ? <CheckCircle className="h-4 w-4 mr-1" /> : <XCircle className="h-4 w-4 mr-1" />}
                                            Enabled: {displayDetails.ctStatus.enabled ? 'Yes' : 'No'}
                                        </p>
                                        <p className="text-sm text-muted-foreground">Logs Count: {displayDetails.ctStatus.logsCount}</p>
                                        {displayDetails.ctStatus.logs && displayDetails.ctStatus.logs.length > 0 && (
                                            <ul className="list-disc pl-5">
                                                {displayDetails.ctStatus.logs.map((log, index) => (
                                                    <li key={index}>
                                                        {log.name}: {log.status} ({log.timestamp})
                                                    </li>
                                                ))}
                                            </ul>
                                        )}
                                    </div>

                                    <Separator />
                                    <h4 className="text-lg font-semibold">Revocation URIs</h4>
                                    <div className="space-y-2">
                                        <p className="text-sm font-medium">CRL:</p>
                                        {displayDetails.revocationUris.crl.length > 0 ? (
                                            <ul className="list-disc pl-5">
                                                {displayDetails.revocationUris.crl.map((uri, index) => <li key={index}>{uri}</li>)}
                                            </ul>
                                        ) : (
                                            <p className="text-sm text-muted-foreground">N/A</p>
                                        )}
                                        <p className="text-sm font-medium">OCSP:</p>
                                        {displayDetails.revocationUris.ocsp.length > 0 ? (
                                            <ul className="list-disc pl-5">
                                                {displayDetails.revocationUris.ocsp.map((uri, index) => <li key={index}>{uri}</li>)}
                                            </ul>
                                        ) : (
                                            <p className="text-sm text-muted-foreground">N/A</p>
                                        )}
                                    </div>

                                    {displayDetails.caaRecords.length > 0 && (
                                        <>
                                            <Separator />
                                            <h4 className="text-lg font-semibold">CAA Records</h4>
                                            <ul className="list-disc pl-5">
                                                {displayDetails.caaRecords.map((record, index) => <li key={index}>{record}</li>)}
                                            </ul>
                                        </>
                                    )}

                                    <Separator />
                                    <h4 className="text-lg font-semibold">Negotiated Protocol & Cipher</h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Negotiated Protocol</p>
                                            <p>{displayDetails.negotiatedProtocol || 'N/A'}</p>
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground">Negotiated Cipher</p>
                                            <p>{displayDetails.negotiatedCipher || 'N/A'}</p>
                                        </div>
                                    </div>

                                    <Separator />
                                    <h4 className="text-lg font-semibold flex items-center">
                                        <Award className="mr-2 h-5 w-5" /> Overall Grade
                                    </h4>
                                    <p className="text-2xl font-bold">{displayDetails.grade || 'N/A'}</p>
                                </div>
                            </div>
                        </div>
                    </Card>
                </div>
            </div>
        </>
    )
}
