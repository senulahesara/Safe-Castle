import { ClipboardPaste, Link as LinkIcon } from "lucide-react";
import { Button } from "./button";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

export function LinkInput() {
    const [inputValue, setInputValue] = useState("");
    const router = useRouter();

    // Function to check if a string is a valid URL
    const isValidUrl = (url: string) => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    };

    // Handle paste from clipboard
    const handlePaste = async () => {
        try {
            const text = await navigator.clipboard.readText();
            setInputValue(text);
        } catch (err) {
            toast.error("Oops!", {
                description: "Couldn't read from your clipboard. Please try again.",
            });
        }
    };

    // Handle check button click
    const handleCheck = () => {
        if (!inputValue.trim()) {
            toast.error("Missing URL", {
                description: "Please enter or paste a URL first.",
            });
            return;
        }

        if (!isValidUrl(inputValue)) {
            toast.error("Invalid URL", {
                description: "Hmm... that doesn’t look like a valid link.",
            });
            return;
        }

        router.push(`/url?url=${encodeURIComponent(inputValue)}`);
    };

    return (
        <>
            <div className="bg-background has-[input:focus]:ring-muted relative grid grid-cols-[1fr_auto_auto] items-center rounded-[0.7rem] border pr-1 shadow shadow-zinc-950/5 has-[input:focus]:ring-1">
                <LinkIcon
                    className="text-muted-foreground pointer-events-none absolute inset-y-0 left-3 my-auto size-5"
                />

                <input
                    placeholder="Enter URL here"
                    className="h-11 w-full bg-transparent pl-10 focus:outline-none"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                />

                <div className="flex gap-2 md:pr-1.5 lg:pr-0">
                    <Button
                        aria-label="paste"
                        variant="secondary"
                        size="icon"
                        className="size-8 cursor-pointer"
                        onClick={handlePaste}
                    >
                        <ClipboardPaste />
                    </Button>

                    <Button
                        aria-label="check"
                        size="sm"
                        className="cursor-pointer"
                        onClick={handleCheck}
                    >
                        <span>Check URL</span>
                    </Button>
                </div>
            </div>
        </>
    );
}
