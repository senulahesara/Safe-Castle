// file: app/api/analyze/route.ts  (Next.js app router style)
import { NextResponse } from "next/server";

const EMAILREP_BASE = "https://emailrep.io";

function extractFromHeaders(headersText: string) {
  const lines = headersText.split(/\r?\n/);
  const receivedHeaders: string[] = [];
  const ipHops: string[] = [];
  let spfResult: string | null = null;
  let dkimResult: string | null = null;
  let dmarcResult: string | null = null;
  let authenticationResults: string | null = null;
  let fromAddress: string | null = null;
  let replyToAddress: string | null = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const low = line.toLowerCase();
    if (low.startsWith("received:")) {
      receivedHeaders.push(line);
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch && !ipHops.includes(ipMatch[0])) ipHops.push(ipMatch[0]);
    }
    if (low.startsWith("authentication-results:")) {
      authenticationResults = (line.substring("authentication-results:".length) || "").trim();
      const spfMatch = authenticationResults.match(/spf=([^; ]+)/);
      if (spfMatch) spfResult = spfMatch[1];
      const dkimMatch = authenticationResults.match(/dkim=([^; ]+)/);
      if (dkimMatch) dkimResult = dkimMatch[1];
      const dmarcMatch = authenticationResults.match(/dmarc=([^; ]+)/);
      if (dmarcMatch) dmarcResult = dmarcMatch[1];
    }
    if (low.startsWith("from:")) {
      fromAddress = line.substring("from:".length).trim().replace(/<|>/g, "");
    }
    if (low.startsWith("reply-to:")) {
      replyToAddress = line.substring("reply-to:".length).trim().replace(/<|>/g, "");
    }
  }

  return { receivedHeaders, ipHops, spfResult, dkimResult, dmarcResult, authenticationResults, fromAddress, replyToAddress };
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const input: string = (body?.input || "").trim();
    if (!input) {
      return NextResponse.json({ error: "No input provided" }, { status: 400 });
    }

    // Simple email regex to decide which path to take
    const emailOnlyMatch = input.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
    if (emailOnlyMatch) {
      // EMAIL path -> query EmailRep.io
      const email = input;
      // EmailRep allows unauthenticated requests but requires a User-Agent header.
      // For production, request a free key from https://emailrep.io/key and include it as "Key" header.
      const resp = await fetch(`${EMAILREP_BASE}/${encodeURIComponent(email)}`, {
        headers: {
          "User-Agent": "Encodea-EmailAnalyzer/1.0 (dev)", // set identifiable UA
          // "Key": process.env.EMAILREP_KEY || "" // uncomment if you set a key
        },
      });

      if (!resp.ok) {
        // if rate-limited or blocked, return the status text
        const text = await resp.text();
        return NextResponse.json({ error: `EmailRep error: ${resp.status} ${resp.statusText}`, raw: text }, { status: resp.status });
      }

      const er = await resp.json();

      // Map EmailRep signals into our AnalysisResult shape
      let verdictType: "safe" | "warning" | "danger" | "info" = "info";
      let plainLanguageSummary = "Analysis complete.";
      let potentialHarm = "General online risks apply.";
      let actionableAdvice = "Use caution and verify unknown senders.";

      const reputation = (er.reputation || "").toString().toLowerCase();
      const suspicious = !!er.suspicious;
      const leaked = !!er.credentials_leaked || !!er.data_breach;
      const blacklisted = !!er.blacklisted;

      if (blacklisted || suspicious || leaked || reputation === "low") {
        verdictType = "danger";
        plainLanguageSummary = `🚨 This email (${email}) looks risky: ${reputation || "suspicious"} (EmailRep).`;
        potentialHarm = "Could be used for scams, phishing or have been compromised.";
        actionableAdvice = "Do not trust requests from this address. Verify via another channel before replying or clicking links.";
      } else if (reputation === "medium" || reputation === "unknown") {
        verdictType = "warning";
        plainLanguageSummary = `⚠️ This email (${email}) has mixed signals: ${reputation}.`;
        potentialHarm = "May be legitimate but caution is advised.";
        actionableAdvice = "Confirm identity via a known channel and avoid sharing secrets.";
      } else if (reputation === "high") {
        verdictType = "safe";
        plainLanguageSummary = `✅ This email (${email}) has a high reputation (looks legitimate).`;
        potentialHarm = "Still possible the owner's account could be compromised, always check content.";
        actionableAdvice = "Okay to proceed after usual checks (hover links, no attachments unless expected).";
      }

      return NextResponse.json({
        verdict: plainLanguageSummary,
        verdictType,
        plainLanguageSummary,
        potentialHarm,
        actionableAdvice,
        receivedHeaders: [],
        ipHops: [],
        spfResult: null,
        dkimResult: null,
        dmarcResult: null,
        authenticationResults: null,
        fromAddress: null,
        replyToAddress: null,
        emailRep: er,
      });
    } else {
      // HEADERS path -> parse locally (no external API)
      const parsed = extractFromHeaders(input);
      // Decide quick verdict from SPF/DKIM/DMARC
      let verdictType: "safe" | "warning" | "danger" | "info" = "info";
      let plainLanguageSummary = "Initial analysis complete. Review details.";
      let potentialHarm = "Not enough information to determine immediate harm. Be cautious.";
      let actionableAdvice = "Check links, attachments and verify sender by another channel.";

      const { spfResult, dkimResult, dmarcResult, fromAddress, replyToAddress } = parsed;

      const isPhishingLikely =
        spfResult === "fail" ||
        dkimResult === "fail" ||
        dmarcResult === "fail" ||
        (fromAddress && replyToAddress && fromAddress.toLowerCase() !== replyToAddress.toLowerCase());

      if (isPhishingLikely) {
        verdictType = "danger";
        plainLanguageSummary = "🚨 DANGER: Headers show strong signs of spoofing or failure of authentication.";
        potentialHarm = "Phishing, credential theft, malware.";
        actionableAdvice = "Do NOT click links/attachments. Mark as spam and verify with the sender via known channels.";
      } else if (spfResult === "softfail" || dkimResult === "temperror" || dkimResult === "permerror") {
        verdictType = "warning";
        plainLanguageSummary = "⚠️ CAUTION: Some authentication checks returned soft failures/errors.";
        potentialHarm = "Might be forged or misconfigured.";
        actionableAdvice = "Proceed carefully and verify.";
      } else if (spfResult === "pass" && dkimResult === "pass") {
        verdictType = "safe";
        plainLanguageSummary = "✅ Authentication passed (SPF & DKIM). Less likely to be spoofed.";
        potentialHarm = "Still possible account is compromised; inspect content.";
        actionableAdvice = "You can be more confident, but verify links/requests.";
      }

      return NextResponse.json({
        verdict: plainLanguageSummary,
        verdictType,
        plainLanguageSummary,
        potentialHarm,
        actionableAdvice,
        ...parsed,
        emailRep: null,
      });
    }
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Server error" }, { status: 500 });
  }
}
