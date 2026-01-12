# SSL/TLS Certificate Tools

A web-based toolkit for analyzing SSL/TLS certificates, decoding PEM files, and decrypting private keys. All sensitive operations are performed client-side using JavaScript.

## Features

### 🔗 Chain Viewer
- Connect to any hostname and port to retrieve the SSL/TLS certificate chain
- Validates certificate installation and chain completeness
- Detects expired certificates, self-signed certs, and hostname mismatches
- OCSP and CRL revocation checking
- CDN/WAF detection (Akamai, Cloudflare, AWS, Azure, etc.)
- STARTTLS support for SMTP (25/587), FTP (21), and PostgreSQL (5432)

### 📄 PEM Decoder
- Decode X.509 certificates and CSRs (Certificate Signing Requests)
- Supports RSA and ECDSA certificates
- Displays subject, issuer, validity, extensions, and SANs
- **Processed entirely in-browser** - your certificates never leave your device

### 🔓 Key Decrypter
- Remove password protection from encrypted private keys
- Supports PKCS#8, traditional RSA, and EC key formats
- Handles AES-128/256, 3DES, and DES encryption
- **Processed entirely in-browser** - your keys never leave your device

### ⚡ Enhanced Vulnerability Scan (Optional)
- Protocol support detection (SSL 2.0/3.0, TLS 1.0 - 1.3)
- Cipher suite enumeration with security ratings
- Security checks:
  - Heartbleed (CVE-2014-0160)
  - OpenSSL CCS Injection (CVE-2014-0224)
  - Secure/Client-Initiated Renegotiation
  - TLS Compression (CRIME attack)
  - Downgrade Prevention (TLS_FALLBACK_SCSV)
  - ROBOT Attack (informational)
  - Weak Cipher Detection (RC4, DES, 3DES, NULL, EXPORT)
- Requires [SSLyze](https://github.com/nabla-c0d3/sslyze) on the server

---

## Quick Start

### Local Development (PHP)

```bash
cd src
php -S localhost:8000
```

Open http://localhost:8000 in your browser.

### Docker

```bash
docker build -t sslviewer .
docker run -p 8000:80 sslviewer
```

Open http://localhost:8000 in your browser.

---

## Requirements

### Frontend Only (PEM Decoder & Key Decrypter)
- Modern web browser with JavaScript enabled
- No server required - can run from `file://` or any static host

### Full Features (Chain Viewer & Vulnerability Scan)
- PHP 8.0+ with OpenSSL and cURL extensions
- OpenSSL CLI (for STARTTLS connections)
- SSLyze (optional, for enhanced vulnerability scanning)

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | HTML, JavaScript |
| Crypto Library | [Forge.js](https://github.com/digitalbazaar/forge) |
| Backend | PHP 8.x |
| Vulnerability Scanner | SSLyze |

---

## Project Structure

```
SSLViewer/
├── src/
│   ├── index.html          # Main application UI
│   ├── verify-cert.php     # Certificate chain retrieval API
│   ├── sslyze-scan.php     # SSLyze vulnerability scan API
│   └── output.css          # Compiled Tailwind CSS
├── Dockerfile              # Docker container definition
```

---

## Security Notes

- **Client-side processing**: PEM decoding and key decryption happen entirely in the browser using Forge.js. Private keys are never transmitted to the server.
- **Server-side connections**: The Chain Viewer connects to remote hosts from the server to retrieve certificates.

---

## License

MIT License
