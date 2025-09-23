import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const analysisId = searchParams.get('analysisId');

  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!analysisId) {
    return NextResponse.json({ message: 'Analysis ID is required.' }, { status: 400 });
  }
  if (!apiKey) {
    console.error("VIRUSTOTAL_API_KEY is not set in environment variables.");
    return NextResponse.json({ message: 'Server configuration error: VirusTotal API Key not found.' }, { status: 500 });
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("VirusTotal report retrieval error:", data);
      if (response.status === 401 || response.status === 403) {
        return NextResponse.json({ message: 'VirusTotal API Key is invalid or expired.' }, { status: response.status });
      }
      return NextResponse.json({ message: data.error?.message || 'Failed to retrieve analysis report from VirusTotal.' }, { status: response.status });
    }

    return NextResponse.json(data);
  } catch (error: any) {
    console.error("API route error during report retrieval:", error);
    return NextResponse.json({ message: 'Internal server error during report retrieval.' }, { status: 500 });
  }
}