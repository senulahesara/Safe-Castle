// pages/api/check-ip.js

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ message: "Method Not Allowed" });
  }

  try {
    const response = await fetch(
      "http://ip-api.com/json/?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,vpn"
    );

    if (!response.ok) {
      throw new Error(`IP API error: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.status === "fail") {
      throw new Error(`IP API failed: ${data.message}`);
    }

    // Map to frontend-friendly keys
    const mappedData = {
      ip: data.query,
      city: data.city,
      region: data.regionName,
      country: data.country,
      isp: data.isp,
      org: data.org,
      proxy: data.proxy,
      vpn: data.vpn,
    };

    res.status(200).json(mappedData);
  } catch (error) {
    console.error("Error fetching IP info:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch IP information", error: error.message });
  }
}
