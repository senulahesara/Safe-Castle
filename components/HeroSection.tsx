'use client'
import { LinkInput } from './ui/link-Input'
import { NavBar } from './NavBar'
import Image from 'next/image'

export function HeroSection() {
    return (
        <>
            <NavBar />
            <main>
                <section className="overflow-hidden">
                    <div className="relative mx-auto max-w-7xl px-6 py-28 lg:py-20">

                        <div className="lg:flex lg:items-center lg:gap-12">
                            <div className="relative z-10 mx-auto max-w-xl text-center lg:ml-0 lg:w-1/2 lg:text-left mt-12">

                                <div className="rounded-lg mx-auto flex w-fit items-center gap-2 border p-1 px-3 lg:ml-0">
                                    <div className="flex items-center justify-center gap-1">
                                        <span className="relative flex h-3 w-3 items-center justify-center">
                                            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500 opacity-75"></span>
                                            <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500"></span>
                                        </span>
                                        <p className="text-xs text-green-500">Available Now</p>
                                    </div>
                                </div>

                                <h1 className="mt-10 text-balance text-4xl font-bold md:text-5xl xl:text-5xl">Your Castle Against Digital Threats</h1>
                                <p className="mt-8">From phishing links to data leaks, defend your online world with one free, open-source toolkit.</p>

                                <div>
                                    <div className="mx-auto my-10 max-w-sm lg:my-12 lg:ml-0 lg:mr-auto">
                                        <LinkInput />
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="absolute inset-0 -mx-4 rounded-3xl p-3 lg:col-span-3">
                            <div aria-hidden className="absolute z-[1] inset-0 bg-gradient-to-r from-background from-35%" />
                            <div className="relative">
                                <Image
                                    className="hidden dark:block"
                                    src="/heroDark.svg"
                                    alt="app illustration"
                                    width={2796}
                                    height={2008}
                                />
                                <Image
                                    className="dark:hidden"
                                    src="/heroLight.svg"
                                    alt="app illustration"
                                    width={2796}
                                    height={2008}
                                />
                            </div>
                        </div>
                    </div>
                </section>
            </main>
        </>
    )
}

