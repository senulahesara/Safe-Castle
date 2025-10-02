export async function GET() {
  try {
    const token = process.env.IPINFO_TOKEN;
    if (!token) {
      throw new Error("Missing IPINFO_TOKEN in environment variables");
    }

    const response = await fetch(`https://ipinfo.io/json?token=${token}`);
    if (!response.ok) {
      throw new Error(`IPInfo API error: ${response.statusText}`);
    }

    const data = await response.json();

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Error fetching IP info:", error);
    return new Response(
      JSON.stringify({
        message: "Failed to fetch IP information",
        error: error.message,
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}
