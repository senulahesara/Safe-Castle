"use client"

import { Feature, FeatureGrid } from '@/components/feature-grid'
import { NavBar } from '@/components/NavBar'
import React from 'react'



// Data for the feature grid, mimicking the provided image
const platformFeatures: Feature[] = [
  {
    imageSrc: "image-KelsTEOQnq22AGUKvLMgBuS0mK4Mzh.png",
    imageAlt: "Phishing URL Guardian",
    title: "Phishing URL Guardian",
    description: "Instantly analyze any URL for safety. Checks domain reputation, SSL/TLS validity, IP geolocation, blacklist status, redirects, and suspicious keywords. offline caching, and a combined risk score (0-100) with real-time updates.",
    href: "/url",
  },
  {
    imageSrc: "image-EvpVqXgiKOwI32jZyyBn5jfgsOUi97.png",
    imageAlt: "Password Strength & Breach Checker",
    title: "Password Strength & Breach Checker",
    description: "Live feedback on password strength, entropy, estimated crack times, and whether your password has appeared in known breaches. Uses the HIBP Pwned Passwords range API via k-anonymity - your full password is NEVER sent to the server.",
    href: "/password",
  },
  {
    imageSrc: "image-SsfjxCJh43Hr1dqzkbFWUGH3ICZQbH.png",
    imageAlt: "Live Threat Map",
    title: "Live Threat Map",
    description: "An interactive live threat map that visualizes global cyberattack activity in real time, showing attack sources, targets, trends, and key insights for cybersecurity monitoring.",
    href: "/map",
  },
  {
    imageSrc: "image-x3jWH9IOEgOOgjk99NJoK1WgftvOP3.png",
    imageAlt: "SSL / TLS Checker",
    title: "SSL / TLS Checker",
    description: "This SSL/TLS Checker lets you instantly analyze any website’s security certificate, showing details like validity, issuer, chain, revocation, supported protocols, ciphers, and overall grade to quickly assess site safety.",
    href: "/ssl",
  },
  {
    imageSrc: "image-GM9MAwFn9U7vdknMcA5533danjh1Ut.png",
    imageAlt: "VPN & Proxy Checker",
    title: "VPN & Proxy Checker",
    description: "Check your IP address details, including location, ISP, ASN, and privacy flags like VPN, proxy, Tor, and hosting, using ipinfo.io.",
    href: "/vpn",
  },
];

export default function page() {
  return (
    <>
      <NavBar />
      <div className="w-full max-w-6xl mx-auto p-4 md:p-8">
        <div className="mb-10 text-center">
          <h1 className="text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
            Your Castle Against Digital Threats
          </h1>
          <p className="mt-4 max-w-3xl mx-auto text-lg text-muted-foreground">
            From phishing links to data leaks, defend your online world with one free, open-source toolkit.
          </p>
        </div>

        <FeatureGrid features={platformFeatures} />
      </div>
    </>
  )
}
