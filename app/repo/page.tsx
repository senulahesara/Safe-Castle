"use client";

import { NavBar } from "@/components/NavBar";
import Image from "next/image";
import Link from "next/link";
import React from "react";

export default function GitHubPreview() {
    const repoImage = "https://opengraph.githubassets.com/1/senulahesara/Safe-Castle";

    return (
        <>
            <NavBar />
            <div className="max-w-7xl mx-auto pt-12">
                <div className="mb-8">
                    <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight dark:text-gray-100 text-black">
                        Github Repository
                    </h1>
                    <p className="mt-2 text-gray-400 max-w-2xl">
                        A preview of the Safe-Castle GitHub repository.
                    </p>
                </div>
            </div>

            <div className="w-full max-w-7xl mx-auto mt-10">
                <Link href="https://github.com/senulahesara/Safe-Castle" target="_blank" rel="noopener noreferrer">
                    <Image
                        src={repoImage}
                        alt="Safe-Castle GitHub Preview"
                        className="w-full h-auto rounded-lg shadow"
                    />
                </Link>
            </div>
        </>
    );
}
