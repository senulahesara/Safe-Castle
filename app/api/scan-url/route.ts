import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  const { url } = await req.json(); // Don't expect apiKey from client

  const apiKey = process.env.VIRUSTOTAL_API_KEY; // Load from server env

  if (!url) {
    return NextResponse.json({ message: 'URL is required.' }, { status: 400 });
  }
  if (!apiKey) {
    console.error("VIRUSTOTAL_API_KEY is not set in environment variables.");
    return NextResponse.json({ message: 'Server configuration error: VirusTotal API Key not found.' }, { status: 500 });
  }

  try {
    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${url}`,
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("VirusTotal URL submission error:", data);
      // Check for specific VirusTotal errors, e.g., invalid API key
      if (response.status === 401 || response.status === 403) {
        return NextResponse.json({ message: 'VirusTotal API Key is invalid or expired.' }, { status: response.status });
      }
      return NextResponse.json({ message: data.error?.message || 'Failed to submit URL to VirusTotal.' }, { status: response.status });
    }

    return NextResponse.json(data);
  } catch (error: any) {
    console.error("API route error during URL submission:", error);
    return NextResponse.json({ message: 'Internal server error during URL submission.' }, { status: 500 });
  }
}