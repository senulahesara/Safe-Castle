"use client";
import { NavBar } from "@/components/NavBar";
import React from "react";

export default function EmbeddedAttackMapsPage() {
  return (
    <>
    <NavBar />
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
