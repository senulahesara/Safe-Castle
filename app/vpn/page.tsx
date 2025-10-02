"use client";

import { NavBar } from "@/components/NavBar";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
} from "@/components/ui/card";
import React, { useEffect, useState } from "react";

export default function Page() {
    const [ipInfo, setIpInfo] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        async function fetchIpInfo() {
            try {
                setLoading(true);
                setError(null);
                const res = await fetch("/api/check-ip");
                if (!res.ok) {
                    throw new Error(`Error: ${res.status}`);
                }
                const data = await res.json();
                setIpInfo(data);
            } catch (err: any) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        }
        fetchIpInfo();
    }, []);

    const renderStatus = (flag?: boolean) => {
        if (flag === undefined || flag === null) {
            return (
                <span className="px-2 py-1 rounded bg-gray-200 text-gray-600 text-sm">
                    Unknown
                </span>
            );
        }
        return flag ? (
            <span className="px-2 py-1 rounded bg-red-100 text-red-700 font-semibold text-sm">
                Yes
            </span>
        ) : (
            <span className="px-2 py-1 rounded bg-green-100 text-green-700 font-semibold text-sm">
                No
            </span>
        );
    };

    return (
        <>
            <NavBar />
            <div className="flex justify-center mt-10 px-4">
                <Card className="w-full max-w-3xl shadow-lg">
                    <CardHeader className="text-2xl md:text-3xl font-bold">
                        VPN & Proxy Checker
                    </CardHeader>
                    <CardDescription className="ml-6">
                        Check your IP address details, including location, ISP, ASN, and
                        privacy flags like VPN, proxy, Tor, and hosting, using ipinfo.io.
                    </CardDescription>
                    <CardContent className="mt-4">

                        {loading && (
                            <p className="text-center text-lg">
                                Checking your IP address...
                            </p>
                        )}

                        {error && (
                            <div className="text-red-700 bg-red-100 border border-red-300 p-4 rounded-md">
                                <p className="font-semibold">Error:</p>
                                <p>{error}</p>
                                <p>Please try again later or check your network connection.</p>
                            </div>
                        )}

                        {!loading && !error && ipInfo && (
                            <div className="space-y-4">
                                <h2 className="text-xl md:text-2xl font-semibold border-b pb-2">
                                    Your IP Information
                                </h2>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <p>
                                            <span className="font-semibold">IP Address:</span>{" "}
                                            <span className="text-blue-700 font-mono">{ipInfo.ip}</span>
                                        </p>
                                        <p>
                                            <span className="font-semibold">Hostname:</span>{" "}
                                            <span className="text-zinc-400">{ipInfo.hostname || "N/A"}</span>
                                        </p>
                                        <p>
                                            <span className="font-semibold">Location:</span>{" "}
                                            <span className="text-zinc-400"> {ipInfo.city}, {ipInfo.region}, {ipInfo.country}</span>
                                        </p>
                                        <p>
                                            <span className="font-semibold">Organization:</span>{" "}
                                            <span className="text-zinc-400"> {ipInfo.org}</span>
                                        </p>
                                    </div>

                                    {ipInfo.asn && (
                                        <div>
                                            <p>
                                                <span className="font-semibold">ASN:</span>{" "}
                                                {ipInfo.asn.asn} ({ipInfo.asn.name})
                                            </p>
                                            <p>
                                                <span className="font-semibold">ASN Domain:</span>{" "}
                                                {ipInfo.asn.domain}
                                            </p>
                                            <p>
                                                <span className="font-semibold">ASN Type:</span>{" "}
                                                {ipInfo.asn.type}
                                            </p>
                                        </div>
                                    )}
                                </div>

                                {ipInfo.privacy && (
                                    <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
                                        <p>
                                            <span className="font-semibold">VPN:</span>{" "}
                                            {renderStatus(ipInfo.privacy.vpn)}
                                        </p>
                                        <p>
                                            <span className="font-semibold">Proxy:</span>{" "}
                                            {renderStatus(ipInfo.privacy.proxy)}
                                        </p>
                                        <p>
                                            <span className="font-semibold">Tor:</span>{" "}
                                            {renderStatus(ipInfo.privacy.tor)}
                                        </p>
                                        <p>
                                            <span className="font-semibold">Hosting:</span>{" "}
                                            {renderStatus(ipInfo.privacy.hosting)}
                                        </p>
                                    </div>
                                )}
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </>
    );
}
