"use client";

import React, { useEffect, useState } from "react";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Eye, EyeOff, Check, X, Key, Clipboard, AlertTriangle } from "lucide-react";
import zxcvbn from "zxcvbn";

interface PasswordStrengthResult {
    score: number;
    feedback: {
        suggestions: string[];
        warning: string;
    };
    crack_times_display: {
        online_throttling_100_per_hour: string;
        online_no_throttling_10_per_second: string;
        offline_fast_hashing_1e10_per_second: string;
        offline_slow_hashing_1e4_per_second: string;
    };
    guesses: number;
}

const strengthLabels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
const badgeBg = ["bg-red-600", "bg-orange-500", "bg-yellow-500", "bg-green-600", "bg-teal-500"];
const progBg = ["bg-red-500", "bg-orange-400", "bg-yellow-400", "bg-green-400", "bg-teal-400"];

const sha1Hex = async (text: string) => {
    // returns uppercase hex SHA-1
    const enc = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-1", enc);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    return hex;
};

const checkPwnedRange = async (password: string): Promise<number | null> => {
    // Returns count of times seen in breach if found, 0 if not found, or null on error.
    if (!password) return null;
    try {
        const sha1 = await sha1Hex(password);
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);
        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            method: "GET",
            // HIBP accepts anonymous GETs; no API key needed for range endpoint.
            // Add Accept header for plain text
            headers: {
                Accept: "text/plain",
            },
        });

        if (!res.ok) {
            // upstream error — return null to indicate we couldn't check
            return null;
        }
        const text = await res.text();
        // Response lines: "SUFFIX:COUNT"
        const lines = text.split("\n");
        for (const line of lines) {
            const [lineSuffix, countStr] = line.trim().split(":");
            if (!lineSuffix) continue;
            if (lineSuffix.toUpperCase() === suffix.toUpperCase()) {
                const count = parseInt(countStr || "0", 10);
                return Number.isFinite(count) ? count : 0;
            }
        }
        return 0; // not found
    } catch (err) {
        // console.error(err);
        return null;
    }
};

// Placeholder for breach details - you would populate this if using an API that provides it
interface BreachDetail {
    name: string;
    year: number;
    description?: string;
}

const PasswordStrengthChecker: React.FC = () => {
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [strengthResult, setStrengthResult] = useState<PasswordStrengthResult | null>(null);

    // breach check states
    const [breachCount, setBreachCount] = useState<number | null>(null);
    const [breachLoading, setBreachLoading] = useState(false);
    const [breachError, setBreachError] = useState<string | null>(null);
    // Placeholder for actual breach details (if available from a more advanced API)
    const [breachDetails, setBreachDetails] = useState<BreachDetail[]>([]);


    // copied state
    const [copied, setCopied] = useState(false);

    // debounce timer id
    useEffect(() => {
        // compute zxcvbn immediately
        if (password) {
            const res = zxcvbn(password) as unknown as PasswordStrengthResult;
            setStrengthResult(res);
        } else {
            setStrengthResult(null); // Clear strength result when password is empty
        }
    }, [password]);

    // Debounced breach check: run after user stops typing for 700ms
    useEffect(() => {
        setBreachCount(null);
        setBreachError(null);
        setBreachDetails([]); // Clear breach details
        if (!password) {
            setBreachLoading(false);
            return;
        }

        let canceled = false;
        setBreachLoading(true);
        const id = setTimeout(async () => {
            // don't run for very short weak passwords (<6) to reduce requests
            if (password.length < 6) {
                if (!canceled) {
                    setBreachLoading(false);
                    setBreachCount(0); // Treat as not breached if too short
                }
                return;
            }
            const count = await checkPwnedRange(password);
            if (canceled) return;
            if (count === null) {
                setBreachError("Could not check breach status (network error).");
                setBreachCount(null);
            } else {
                setBreachCount(count);
                // In a real scenario, if count > 0, you'd make another API call
                // to get specific breach details like name and year if available
                // from a more advanced HIBP API endpoint or a different service.
                // For this example, we'll just show a generic message.
                if (count > 0) {
                    // This is a placeholder. You'd replace this with actual data from a backend/API.
                    setBreachDetails([{ name: "Unknown Data Breach", year: new Date().getFullYear(), description: "Detailed breach information not available via k-anonymity API." }]);
                }
            }
            setBreachLoading(false);
        }, 700);

        return () => {
            canceled = true;
            clearTimeout(id);
        };
    }, [password]);

    const togglePasswordVisibility = () => setShowPassword((s) => !s);

    const generateStrongPassword = (length = 20) => {
        const charset =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        const newPwd = Array.from(array, (b) => charset[b % charset.length]).join("");
        setPassword(newPwd);
    };

    const copyToClipboard = async () => {
        if (!password) return;
        try {
            await navigator.clipboard.writeText(password);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // ignore
        }
    };

    // requirement flags
    const hasMinLength = password.length >= 12;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    const ChecklistItem: React.FC<{ condition: boolean; label: string }> = ({ condition, label }) => (
        <li
            className={`flex items-center text-sm transition-all duration-300 ${password ? (condition ? "text-green-400 line-through" : "text-gray-400") : "text-gray-500"
                }`}
        >
            {password ? (
                condition ? (
                    <Check className="w-4 h-4 mr-2 text-green-500" />
                ) : (
                    <X className="w-4 h-4 mr-2 text-gray-400" />
                )
            ) : (
                <X className="w-4 h-4 mr-2 text-gray-500" />
            )}
            {label}
        </li>
    );

    // derived data for display
    const score = strengthResult ? strengthResult.score : -1;
    const progressValue = password ? (score + 1) * 20 : 0;
    const scoreLabel = password ? strengthLabels[score] : "N/A";
    const badgeClass = password ? badgeBg[score] : "bg-gray-500";
    const progClass = password ? progBg[score] : "bg-gray-500";

    const entropy = strengthResult ? Math.log2(strengthResult.guesses || 1) : 0;

    return (
        <div className="min-h-screen dark:bg-black bg-white py-12 px-6">
            <div className="max-w-7xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight dark:text-gray-100 text-black">
                        Password Strength & Breach Checker
                    </h1>
                    <p className="mt-2 text-gray-400 max-w-2xl">
                        Live feedback on password strength, entropy, estimated crack times, and whether your password
                        has appeared in known breaches. Uses the HIBP Pwned Passwords range API via  k-anonymity - your full
                        password is <strong>NEVER</strong> sent to the server.
                    </p>
                </div>

                <Card className="shadow-2xl overflow-hidden dark:bg-black bg-white">
                    <div className="md:flex flex-col md:flex-row">
                        {/* RIGHT: INPUT + ACTIONS (desktop right column; mobile stacked above details) */}
                        <div className="md:w-1/2 p-6 md:p-10 dark:bg-black bg-white order-first md:order-none"> {/* Added order-first for mobile */}
                            <div className="max-w-xl mx-auto">


                            </div>
                        </div>

                        {/* LEFT: DETAILS (desktop: visible as left column, mobile: below input) */}
                        <div className="md:w-1/2 dark:bg-black bg-white p-6 md:p-8 border-t md:border-t-0 md:border-l md:border-gray-700 md:order-last"> {/* Added md:order-last for mobile */}

                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
};

export default PasswordStrengthChecker;