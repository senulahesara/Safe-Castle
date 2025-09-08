import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'crypto';

export async function POST(req: NextRequest) {
    const { url } = await req.json();

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!url) {
        return NextResponse.json({ message: 'URL is required.' }, { status: 400 });
    }
    if (!apiKey) {
        console.error("VIRUSTOTAL_API_KEY is not set in environment variables.");
        return NextResponse.json({ message: 'Server configuration error: VirusTotal API Key not found.' }, { status: 500 });
    }

    try {
        // Compute urlId for VirusTotal API
        let urlId = Buffer.from(url, 'utf8').toString('base64');
        urlId = urlId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        // Compute urlHash for GUI link
        const urlHash = createHash('sha256').update(url).digest('hex').toLowerCase();

        // First, try to get existing analysis
        const getResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        if (getResponse.ok) {
            const getData = await getResponse.json();
            const lastAnalysisDate = getData.data.attributes.last_analysis_date;
            const now = Math.floor(Date.now() / 1000);
            const RECENT_THRESHOLD = 86400; // 1 day in seconds

            if (now - lastAnalysisDate < RECENT_THRESHOLD) {
                // Use existing recent analysis
                const existingAnalysis = {
                    id: `existing_${urlId}`,
                    attributes: {
                        stats: getData.data.attributes.last_analysis_stats,
                        status: 'completed',
                        date: lastAnalysisDate,
                    },
                };
                return NextResponse.json({
                    analysis: existingAnalysis,
                    urlHash,
                    needsPoll: false,
                });
            } else {
                // Re-analyze if old
                const reAnalyzeResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}/analyse`, {
                    method: 'POST',
                    headers: {
                        'x-apikey': apiKey,
                    },
                });

                const reAnalyzeData = await reAnalyzeResponse.json();

                if (!reAnalyzeResponse.ok) {
                    console.error("VirusTotal re-analysis error:", reAnalyzeData);
                    if (reAnalyzeResponse.status === 401 || reAnalyzeResponse.status === 403) {
                        return NextResponse.json({ message: 'VirusTotal API Key is invalid or expired.' }, { status: reAnalyzeResponse.status });
                    }
                    return NextResponse.json({ message: reAnalyzeData.error?.message || 'Failed to re-analyze URL with VirusTotal.' }, { status: reAnalyzeResponse.status });
                }

                return NextResponse.json({
                    data: reAnalyzeData.data,
                    urlHash,
                    needsPoll: true,
                });
            }
        } else if (getResponse.status === 404) {
            // Submit new analysis if not found
            const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: {
                    'x-apikey': apiKey,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(url)}`,
            });

            const submitData = await submitResponse.json();

            if (!submitResponse.ok) {
                console.error("VirusTotal URL submission error:", submitData);
                if (submitResponse.status === 401 || submitResponse.status === 403) {
                    return NextResponse.json({ message: 'VirusTotal API Key is invalid or expired.' }, { status: submitResponse.status });
                }
                return NextResponse.json({ message: submitData.error?.message || 'Failed to submit URL to VirusTotal.' }, { status: submitResponse.status });
            }

            return NextResponse.json({
                data: submitData.data,
                urlHash,
                needsPoll: true,
            });
        } else {
            const errorData = await getResponse.json();
            console.error("VirusTotal get URL error:", errorData);
            return NextResponse.json({ message: errorData.error?.message || 'Failed to check existing URL analysis.' }, { status: getResponse.status });
        }
    } catch (error: any) {
        console.error("API route error during URL submission:", error);
        return NextResponse.json({ message: 'Internal server error during URL submission.' }, { status: 500 });
    }
}