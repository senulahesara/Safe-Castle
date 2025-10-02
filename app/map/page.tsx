"use client";
import { NavBar } from "@/components/NavBar";
import React from "react";

export default function EmbeddedAttackMapsPage() {
  return (
    <>
      <NavBar />
      <div className="max-w-7xl pt-12 mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight dark:text-gray-100 text-black">
            Live Threat Map
          </h1>
          <p className="mt-2 text-gray-400 max-w-2xl">
            An interactive live threat map that visualizes global cyberattack activity in real time, showing attack sources, targets, trends, and key insights for cybersecurity monitoring.
          </p>
        </div>
      </div>
      <div className="w-7xl h-[800px] m-auto mt-10">
        <iframe
          src="https://threatmap.checkpoint.com"
          title="Checkpoint ThreatMap"
          className="w-full h-full border-0"
          allowFullScreen
        >
        </iframe>
      </div>

    </>
  );
}
