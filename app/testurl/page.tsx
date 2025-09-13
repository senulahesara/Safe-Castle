import { Button } from "@/components/ui/button";
import { ClipboardPaste, Link, Mail, SendHorizonal } from "lucide-react";

export default function Home() {
    return (

        <>
            <div>
                <h1>Test URL Page</h1>
                <p>This is a test page to verify routing in Next.js 13.</p>
            </div>
            <div className="mx-auto my-10 max-w-sm lg:my-6 lg:ml-0 lg:mr-auto">
                <div className="bg-background has-[input:focus]:ring-muted relative grid grid-cols-[1fr_auto_auto] items-center rounded-[0.7rem] border pr-1 shadow shadow-zinc-950/5 has-[input:focus]:ring-1">
                    <Link
                        className="text-muted-foreground pointer-events-none absolute inset-y-0 left-3 my-auto size-5"
                    />

                    <input
                        placeholder="Enter URL here"
                        className="h-11 w-full bg-transparent pl-10 focus:outline-none"
                        type="email"
                    />

                    <div className="flex gap-2 md:pr-1.5 lg:pr-0">
                        <Button
                            aria-label="submit"
                            variant="secondary"
                            size="icon"
                            className="size-8 cursor-pointer"
                        >
                            <ClipboardPaste />
                        </Button>

                        <Button
                            aria-label="submit"
                            size="sm"
                            className="cursor-pointer">
                            <span>Check</span>
                        </Button>
                    </div>
                </div>
            </div>

        </>
    );
}