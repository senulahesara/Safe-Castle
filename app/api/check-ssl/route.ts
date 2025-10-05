import { NextResponse } from 'next/server';
import tls from 'tls';

interface CertificateDetail {
    domain: string;
    validity: string;
    issuer: string;
    commonName: string;
    expiryDate: string;
    startDate: string;
    serialNumber: string;
    signatureAlgorithm: string;
    publicKeyAlgorithm: string;
    publicKeySize: number;
    keyUsages: string[];
    extendedKeyUsages: string[];
    ciphers: {
        name: string;
        strength: string;
        forwardSecrecy: boolean;
    }[];
    hsts: boolean;
    tlsVersions: string[];
    subjectAltNames: string[];
    isSelfSigned: boolean;
    isExpired: boolean;
    dnsStatus: string;
    certificateChain: {
        commonName: string;
        issuer: string;
        validity: string;
        serialNumber: string;
        publicKeySize: number;
    }[];
    ocspStapling: {
        enabled: boolean;
        responseStatus: string;
        nextUpdate: string;
    };
    ctStatus: {
        enabled: boolean;
        logsCount: number;
        logs: string;
    };
    revocationUris: {
        crl: string[];
        ocsp: string[];
    };
    caaRecords: string[];
    negotiatedProtocol: string;
    negotiatedCipher: string;
    grade: string;
}

// 🔹 TLS handshake fallback (to get protocol & cipher if API doesn’t return them)
async function handshakeProtocolAndCipher(
    host: string,
    port = 443
): Promise<{ protocol: string; cipher: string }> {
    return new Promise((resolve, reject) => {
        const socket = tls.connect(port, host, { servername: host }, () => {
            const cipherInfo = socket.getCipher();
            const protocol = socket.getProtocol();
            socket.end();

            resolve({
                protocol: protocol || "N/A",
                cipher: cipherInfo?.name || "N/A",
            });
        });
        socket.on('error', (err) => reject(err));
    });
}

export async function GET(request: Request) {
    const { searchParams } = new URL(request.url);
    const domain = searchParams.get('domain');

    if (!domain) {
        return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
    }

    try {
        const apiUrl = `https://ssl-checker.io/api/v1/check/${domain}`;
        const response = await fetch(apiUrl);

        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }

        const apiData = await response.json();
        const certData = apiData.result || apiData;

        // 🛠 fallback TLS handshake
        let fallbackProt = "N/A";
        let fallbackCipher = "N/A";
        if (!certData.negotiated_protocol || !certData.negotiated_cipher) {
            try {
                const { protocol, cipher } = await handshakeProtocolAndCipher(domain);
                fallbackProt = protocol;
                fallbackCipher = cipher;
            } catch (err) {
                console.error("Handshake fallback failed:", err);
            }
        }

        const mapped: CertificateDetail = {
            domain,
            validity:
                new Date(certData.valid_till) < new Date()
                    ? "Expired"
                    : certData.cert_valid
                        ? "Valid"
                        : "Invalid",
            issuer: certData.issuer_o
                ? `${certData.issuer_cn || "Unknown"} (${certData.issuer_o})`
                : certData.issuer_cn || "Unknown",
            commonName: certData.issued_to || domain,
            expiryDate: certData.valid_till,
            startDate: certData.valid_from,
            serialNumber: certData.cert_sn || "",
            signatureAlgorithm: certData.cert_alg || "Unknown",
            publicKeyAlgorithm: certData.cert_pubkey_alg || "RSA",
            publicKeySize: certData.cert_pubkey_size || 0,
            keyUsages: certData.cert_key_usage || [],
            extendedKeyUsages: certData.cert_ext_key_usage || [],
            ciphers: (certData.ciphers || []).map((c: { name: string; strength: string; forward_secrecy: string; }) => ({
                name: c.name || "Unknown",
                strength: c.strength || "Unknown",
                forwardSecrecy: !!c.forward_secrecy,
            })),
            hsts: certData.hsts === true || certData.hsts?.enabled === true,
            tlsVersions: certData.tls_versions || [],
            subjectAltNames: certData.cert_sans
                ? certData.cert_sans
                    .split(';')
                    .map((san: string) => san.replace('DNS:', '').trim())
                    .filter((s: string) => s)
                : [],
            isSelfSigned: !!certData.cert_self_signed,
            isExpired: new Date(certData.valid_till) < new Date(),
            dnsStatus: certData.dns_valid ? "OK" : "Failed",
            certificateChain: (certData.chain || []).map((c: { cn: string; issuer: string; validity: string; sn: string; pubkey_size: string; }) => ({
                commonName: c.cn || "Unknown",
                issuer: c.issuer || "Unknown",
                validity: c.validity || "Unknown",
                serialNumber: c.sn || "",
                publicKeySize: c.pubkey_size,
            })),
            ocspStapling: {
                enabled: !!certData.ocsp_stapling,
                responseStatus: certData.ocsp_response_status || "N/A",
                nextUpdate: certData.ocsp_next_update || "N/A",
            },
            ctStatus: {
                enabled: !!certData.ct,
                logsCount: (certData.ct_logs || []).length,
                logs: certData.ct_logs || [],
            },
            revocationUris: {
                crl: certData.crl_urls || ["N/A"],
                ocsp: certData.ocsp_urls || ["N/A"],
            },
            caaRecords: certData.caa || [],
            negotiatedProtocol:
                certData.negotiated_protocol || fallbackProt || "N/A",
            negotiatedCipher:
                certData.negotiated_cipher || fallbackCipher || "N/A",
            grade: certData.grade || "N/A",
        };

        return NextResponse.json(mapped);
    } catch (err) {
        console.error("SSL check error:", err);
        return NextResponse.json(
            { error: "Failed to fetch SSL details", details: (err as Error).message },
            { status: 500 }
        );
    }
}
