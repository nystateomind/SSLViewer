<?php
/**
 * SSL/TLS Certificate Verifier API
 *
 * This script connects to a specified host and port to retrieve the SSL/TLS 
 * certificate chain and returns it as a JSON object. It intelligently handles
 * different protocols based on the port number.
 */

// Include enterprise-specific detection (optional - create this file for custom IP-based detection)
if (file_exists(__DIR__ . '/enterprise-config.php')) {
    require_once __DIR__ . '/enterprise-config.php';
}

// Set the content type to JSON for all responses
header("Content-Type: application/json");

/**
 * Sends a JSON error response and terminates the script.
 * @param string $message The error message.
 * @param int $statusCode The HTTP status code.
 */
function send_error($message, $statusCode = 400)
{
    if (!headers_sent()) {
        http_response_code($statusCode);
    }
    echo json_encode(['error' => $message]);
    exit;
}

// --- Custom Error Handlers ---
function json_error_handler($severity, $message, $file, $line)
{
    if (error_reporting() & $severity) {
        // In a production environment, log this instead of outputting file/line
        send_error("Server Error: A technical issue occurred.", 500);
    }
}
set_error_handler('json_error_handler');

function fatal_error_shutdown_handler()
{
    $last_error = error_get_last();
    if ($last_error && ($last_error['type'] === E_ERROR || $last_error['type'] === E_PARSE)) {
        // In a production environment, log this instead of outputting file/line
        send_error("Fatal Server Error: A critical issue occurred.", 500);
    }
}
register_shutdown_function('fatal_error_shutdown_handler');


/**
 * Parses a block of text containing one or more PEM certificates.
 * @param string $pemBlock The block of text.
 * @return array An array of PEM certificate strings.
 */
function parse_pem_certs($pemBlock)
{
    $certs = [];
    $pattern = '/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/s';
    preg_match_all($pattern, $pemBlock, $matches);
    if (!empty($matches[1])) {
        $certs = $matches[1];
    }
    return $certs;
}

/**
 * Formats a distinguished name array from openssl_x509_parse into a string.
 * @param array $dn The distinguished name array.
 * @return string The formatted DN string.
 */
function format_distinguished_name(array $dn)
{
    $parts = [];
    foreach ($dn as $key => $value) {
        if (is_array($value)) {
            // Handle multi-valued RDNs (e.g., multiple OU attributes)
            foreach ($value as $sub_value) {
                $parts[] = "{$key}=" . htmlspecialchars($sub_value);
            }
        } else {
            $parts[] = "{$key}=" . htmlspecialchars($value);
        }
    }
    return implode(', ', $parts);
}


// --- Main execution in a try-catch block ---
try {
    // --- Input Validation ---
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method. Only POST is accepted.', 405);
    }

    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON in request body.', 400);
    }

    // Sanitize hostname input
    $hostname = isset($input['hostname']) ? trim($input['hostname']) : '';

    // Check for wildcard hostname entry (e.g., *.domain.tld) before sanitizing
    if (preg_match('/^\s*\*\./', $hostname)) {
        throw new Exception('To validate a wildcard certificate, enter a hostname it\'s installed on.');
    }

    // Remove leading non-hostname characters (bullets, spaces, dashes, etc.)
    $hostname = preg_replace('/^[^a-zA-Z0-9]+/', '', $hostname);
    // Remove protocol prefixes and anything with *// pattern (e.g., https://, http://, *//, etc.)
    $hostname = preg_replace('/^.*\/\//', '', $hostname);
    // Remove any path, query string, or fragment after the hostname
    $hostname = preg_replace('/[\/?#].*$/', '', $hostname);
    // Remove any trailing colon and port number if included in hostname
    $hostname = preg_replace('/:\d+$/', '', $hostname);
    // Final trim in case of any remaining whitespace
    $hostname = trim($hostname);

    // Sanitize port input (trim whitespace before converting to int)
    $port = isset($input['port']) ? (int) trim($input['port']) : 0;

    if (empty($hostname) || filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new Exception('A valid hostname is required.');
    }

    if ($port <= 0 || $port > 65535) {
        throw new Exception('A valid port number (1-65535) is required.');
    }

    // --- Certificate Retrieval ---
    $rawCerts = [];

    // Determine if we need STARTTLS for specific protocols
    $starttlsProtocol = null;
    if ($port === 5432) {
        $starttlsProtocol = 'postgres';
    } elseif ($port === 25 || $port === 587) {
        $starttlsProtocol = 'smtp';
    } elseif ($port === 21) {
        $starttlsProtocol = 'ftp';
    }

    if ($starttlsProtocol !== null) {
        // --- Use OpenSSL for services with STARTTLS ---
        $command = "openssl s_client -starttls {$starttlsProtocol} -showcerts -connect " . escapeshellarg("$hostname:$port");

        $descriptorSpec = [
            0 => ["pipe", "r"], // stdin
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"]  // stderr
        ];

        $process = proc_open($command, $descriptorSpec, $pipes, null, null);

        if (!is_resource($process)) {
            throw new Exception("Failed to create the OpenSSL process. Check server permissions and configuration.", 500);
        }

        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $error_output = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        proc_close($process);

        if (empty($output) && !empty($error_output)) {
            throw new Exception("OpenSSL command failed.", 500);
        }

        if (strpos($output, '-----BEGIN CERTIFICATE-----') === false) {
            throw new Exception("Failed to connect or perform STARTTLS.", 500);
        }

        $rawCerts = parse_pem_certs($output);
        if (empty($rawCerts)) {
            throw new Exception("Connected, but could not parse a valid certificate from the output.", 500);
        }

    } else {
        // --- Use cURL for standard HTTPS ---
        if (!function_exists('curl_init')) {
            throw new Exception('The cURL extension is not installed or enabled on this server.', 500);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://{$hostname}:{$port}");
        curl_setopt($ch, CURLOPT_PORT, $port);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_CERTINFO, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // Don't follow redirects - capture initial response headers
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_HEADER, true); // Include headers in output
        // Add Akamai debug headers to reveal CDN info
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key'
        ]);

        $response = curl_exec($ch);
        $certChainInfo = curl_getinfo($ch, CURLINFO_CERTINFO);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headerSize);

        // Extract Server header and detect CDN/WAF
        $serverHeader = null;
        if (preg_match('/^Server:\s*(.+)$/mi', $headers, $matches)) {
            $serverHeader = trim($matches[1]);
        }

        // Detect CDN/WAF from headers when Server header is missing or generic
        $cdnDetected = null;

        // Enterprise-specific detection (runs FIRST, uses DNS lookup for IP-based detection)
        if (function_exists('enterprise_detect_infrastructure')) {
            $ipAddress = gethostbyname($hostname);
            $cdnDetected = enterprise_detect_infrastructure($hostname, $ipAddress, $headers);
        }

        // Generic detection using combined regex patterns (only if enterprise didn't match)
        if ($cdnDetected === null) {
            // CDN/WAF detection patterns (combined for performance)
            $cdnPatterns = [
                'Akamai' => '/^(X-Akamai-|Akamai-|X-True-Cache-Key:|X-Cache:.*(?:akamaitechnologies\.com|AkamaiGHost))/mi',
                'Cloudflare' => '/^(CF-RAY:|CF-Cache-Status:|Server:\s*cloudflare)/mi',
                'Fastly' => '/^(X-Served-By:.*cache|Fastly-|X-Fastly-)/mi',
                'AWS CloudFront' => '/^(X-Amz-Cf-Id:|X-Amz-Cf-Pop:|Via:.*CloudFront)/mi',
                'AWS API Gateway' => '/^(x-amz-apigw-id:|x-amzn-requestid:)/mi',
                'Azure CDN' => '/^(X-Azure-Ref:|X-MSEdge-Ref:)/mi',
                'Google Cloud CDN' => '/^Via:.*google/mi',
                'Varnish' => '/^X-Varnish:/mi',
                'Imperva/Incapsula' => '/^(X-Iinfo:|X-CDN:)/mi',
                'Sucuri' => '/^X-Sucuri-ID:/mi',
                // Load Balancers
                'VMware Avi' => '/^(Server:\s*AVI|X-Avi-)/mi',
                'HAProxy' => '/^(X-Haproxy-|Via:.*haproxy)/mi',
                'F5 BIG-IP' => '/^(Server:\s*BigIP|X-Cnection:|Set-Cookie:.*BIGip)/mi',
                'Citrix NetScaler' => '/^(Via:.*NS-CACHE|Cneonction:|nnCoection:|Set-Cookie:\s*NSC_|X-NS-)/mi',
                'AWS ALB/ELB' => '/^(X-Amzn-Trace-Id:|Server:\s*awselb)/mi',
                'Envoy' => '/^(Server:\s*envoy|X-Envoy-)/mi',
                'Traefik' => '/^Server:\s*Traefik/mi',
                'Apache Traffic Server' => '/^(Via:.*ApacheTrafficServer|Server:\s*ATS)/mi',
                'LiteSpeed' => '/^Server:\s*LiteSpeed/mi',
                'Kong Gateway' => '/^(Via:.*kong|X-Kong-)/mi',
                'Microsoft IIS' => '/^(X-Powered-By:\s*ASP\.NET|X-AspNet-Version:|X-AspNetMvc-Version:|Set-Cookie:\s*(?:ASP\.NET_SessionId|ASPSESSIONID))/mi',
                'Apache Tomcat' => '/^(Server:\s*Apache-Coyote|Server:\s*Apache Tomcat|X-Powered-By:\s*(?:Servlet|JSP)|Set-Cookie:\s*JSESSIONID=)/mi',
            ];

            foreach ($cdnPatterns as $name => $pattern) {
                if (preg_match($pattern, $headers)) {
                    $cdnDetected = $name;
                    break;
                }
            }
        }

        // If CDN/LB detected but no/generic Server header, use detected name
        if ($cdnDetected && (empty($serverHeader) || in_array(strtolower($serverHeader), ['akamaighost', 'apache', 'nginx', 'microsoft-iis']))) {
            $serverHeader = $cdnDetected . ($serverHeader ? ' (' . $serverHeader . ')' : '');
        }

        if (curl_errno($ch)) {
            if (empty($certChainInfo)) {
                throw new Exception('Error: ' . curl_error($ch), 500);
            }
        }
        curl_close($ch);

        if (!empty($certChainInfo)) {
            foreach ($certChainInfo as $certData) {
                if (!empty($certData['Cert'])) {
                    $rawCerts[] = $certData['Cert'];
                }
            }
        }
    }

    if (empty($rawCerts)) {
        throw new Exception("Failed to retrieve certificate chain from {$hostname}:{$port}.", 404);
    }

    // --- Certificate Parsing ---
    $certificates = [];
    $isLeaf = true;

    foreach ($rawCerts as $pemCert) {
        $certResource = openssl_x509_read($pemCert);
        if ($certResource === false)
            continue;

        $certInfo = openssl_x509_parse($certResource);
        if ($certInfo === false)
            continue;

        $subjectCnValue = $certInfo['subject']['CN'] ?? 'N/A';
        $subjectCn = is_array($subjectCnValue) ? implode(', ', $subjectCnValue) : $subjectCnValue;

        $type = $isLeaf ? 'Leaf' : 'Intermediate';
        if ($certInfo['subject'] === $certInfo['issuer']) {
            $type = $isLeaf ? 'Self-Signed Certificate' : 'Root Certificate';
        }

        $publicKeyDetails = openssl_pkey_get_details(openssl_pkey_get_public($certResource));
        $keyTypeStr = 'N/A';
        $keyBits = 0;
        if ($publicKeyDetails && isset($publicKeyDetails['type'])) {
            $keyBits = $publicKeyDetails['bits'] ?? 0;
            switch ($publicKeyDetails['type']) {
                case OPENSSL_KEYTYPE_RSA:
                    $keyTypeStr = 'RSA';
                    break;
                case OPENSSL_KEYTYPE_DSA:
                    $keyTypeStr = 'DSA';
                    break;
                case OPENSSL_KEYTYPE_DH:
                    $keyTypeStr = 'DH';
                    break;
                case OPENSSL_KEYTYPE_EC:
                    $keyTypeStr = 'EC';
                    $keyBits = isset($publicKeyDetails['ec']['curve_bits']) ? $publicKeyDetails['ec']['curve_bits'] : $keyBits;
                    break;
                default:
                    $keyTypeStr = 'Unknown';
                    break;
            }
        }
        $publicKeyString = sprintf('%s (%d bits)', $keyTypeStr, $keyBits);

        $certificates[] = [
            'type' => $type,
            'pem' => $pemCert, // Include raw PEM for download
            'commonName' => $subjectCn,
            'alternativeNames' => isset($certInfo['extensions']['subjectAltName']) ? array_map('trim', explode(',', str_replace('DNS:', '', $certInfo['extensions']['subjectAltName']))) : [],
            'serialNumberHex' => $certInfo['serialNumberHex'] ?? 'N/A',
            'serialNumberDecimal' => $certInfo['serialNumber'] ?? 'N/A',
            'validFrom' => isset($certInfo['validFrom_time_t']) ? gmdate("Y-m-d\TH:i:s\Z", $certInfo['validFrom_time_t']) : 'N/A',
            'validUntil' => isset($certInfo['validTo_time_t']) ? gmdate("Y-m-d\TH:i:s\Z", $certInfo['validTo_time_t']) : 'N/A',
            'publicKey' => $publicKeyString,
            'issuer' => isset($certInfo['issuer']) ? format_distinguished_name($certInfo['issuer']) : 'N/A',
            'signatureAlgorithm' => $certInfo['signatureTypeSN'] ?? 'N/A',
        ];
        $isLeaf = false;
    }

    if (empty($certificates)) {
        throw new Exception("Successfully connected, but failed to parse any certificates from the chain.", 500);
    }

    // --- Chain Status Analysis ---
    $chainStatus = [
        'isValid' => true,
        'issues' => [],
        'summary' => ''
    ];

    // Check for issues in the certificate chain
    $hasExpiredCert = false;
    $hasSelfSigned = false;
    $isIncompleteChain = false;
    $hostnameInSan = false;
    $revocationStatus = 'unknown';

    foreach ($certificates as $index => $cert) {
        // Check for expired certificates
        $validUntil = new DateTime($cert['validUntil']);
        $now = new DateTime();
        if ($validUntil < $now) {
            $hasExpiredCert = true;
            $chainStatus['issues'][] = "Expired certificate: {$cert['commonName']} (expired {$cert['validUntil']})";
        }

        // Check for self-signed leaf certificate
        if ($cert['type'] === 'Self-Signed Certificate') {
            $hasSelfSigned = true;
            $chainStatus['issues'][] = "Self-signed certificate detected: {$cert['commonName']}";
        }

        // Check if hostname is in SAN (only for leaf certificate)
        if ($index === 0) {
            $leafCert = $cert;
            // Check CN
            if (strcasecmp($cert['commonName'], $hostname) === 0) {
                $hostnameInSan = true;
            }
            // Check SANs
            if (!empty($cert['alternativeNames'])) {
                foreach ($cert['alternativeNames'] as $san) {
                    $san = trim($san);
                    // Exact match
                    if (strcasecmp($san, $hostname) === 0) {
                        $hostnameInSan = true;
                        break;
                    }
                    // Wildcard match (*.example.com matches sub.example.com)
                    if (strpos($san, '*.') === 0) {
                        $wildcardDomain = substr($san, 2);
                        $hostnameParts = explode('.', $hostname, 2);
                        if (count($hostnameParts) === 2 && strcasecmp($hostnameParts[1], $wildcardDomain) === 0) {
                            $hostnameInSan = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Add hostname not in SAN warning
    if (!$hostnameInSan) {
        $chainStatus['issues'][] = "Hostname '{$hostname}' is not listed in the certificate's Subject Alternative Names (SAN)";
    }

    // Check for incomplete chain (only leaf certificate, no intermediate)
    if (count($certificates) === 1 && !$hasSelfSigned) {
        $isIncompleteChain = true;
        $chainStatus['issues'][] = "Incomplete chain: Missing intermediate certificate(s)";
    }

    // --- OCSP Revocation Check for leaf certificate ---
    if (!empty($rawCerts[0]) && count($rawCerts) >= 2) {
        $leafPem = $rawCerts[0];
        $issuerPem = $rawCerts[1]; // Issuer is usually second in chain

        $certResource = openssl_x509_read($leafPem);
        if ($certResource) {
            $certInfo = openssl_x509_parse($certResource);

            // Check for OCSP URL in Authority Information Access
            $ocspUrl = null;
            if (isset($certInfo['extensions']['authorityInfoAccess'])) {
                if (preg_match('/OCSP\s*-\s*URI:(\S+)/i', $certInfo['extensions']['authorityInfoAccess'], $matches)) {
                    $ocspUrl = $matches[1];
                }
            }

            if ($ocspUrl) {
                // Create temp files for OCSP check
                $leafFile = tempnam(sys_get_temp_dir(), 'leaf_');
                $issuerFile = tempnam(sys_get_temp_dir(), 'issuer_');

                file_put_contents($leafFile, $leafPem);
                file_put_contents($issuerFile, $issuerPem);

                // Run OCSP check
                $ocspCommand = sprintf(
                    'openssl ocsp -issuer %s -cert %s -url %s -no_nonce 2>&1',
                    escapeshellarg($issuerFile),
                    escapeshellarg($leafFile),
                    escapeshellarg($ocspUrl)
                );

                $ocspOutput = shell_exec($ocspCommand);

                // Clean up temp files
                @unlink($leafFile);
                @unlink($issuerFile);

                // Parse OCSP response
                if ($ocspOutput !== null) {
                    if (stripos($ocspOutput, ': good') !== false) {
                        $revocationStatus = 'good';
                    } elseif (stripos($ocspOutput, ': revoked') !== false) {
                        $revocationStatus = 'revoked';
                        $chainStatus['issues'][] = "Certificate has been REVOKED";
                        $chainStatus['isValid'] = false;
                    } elseif (stripos($ocspOutput, 'error') !== false || stripos($ocspOutput, 'unauthorized') !== false) {
                        $revocationStatus = 'ocsp_error';
                    } else {
                        $revocationStatus = 'ocsp_unknown';
                    }
                } else {
                    $revocationStatus = 'ocsp_error';
                }
            } else {
                $revocationStatus = 'no_ocsp';
            }
        }
    } elseif (!empty($rawCerts[0])) {
        // Only have leaf cert, check if OCSP URL exists
        $certResource = openssl_x509_read($rawCerts[0]);
        if ($certResource) {
            $certInfo = openssl_x509_parse($certResource);
            if (
                isset($certInfo['extensions']['authorityInfoAccess']) &&
                stripos($certInfo['extensions']['authorityInfoAccess'], 'OCSP') !== false
            ) {
                $revocationStatus = 'ocsp_available';
            } else {
                $revocationStatus = 'no_ocsp';
            }
        }
    }

    // --- CRL Fallback if OCSP failed or not available ---
    if (in_array($revocationStatus, ['no_ocsp', 'ocsp_error', 'ocsp_unknown', 'error', 'unknown']) && !empty($rawCerts[0])) {
        $leafPem = $rawCerts[0];
        $certResource = openssl_x509_read($leafPem);
        if ($certResource) {
            $certInfo = openssl_x509_parse($certResource);

            // Check for CRL Distribution Points
            $crlUrl = null;
            if (isset($certInfo['extensions']['crlDistributionPoints'])) {
                if (preg_match('/URI:(\S+)/i', $certInfo['extensions']['crlDistributionPoints'], $matches)) {
                    $crlUrl = $matches[1];
                }
            }

            if ($crlUrl) {
                // Get certificate serial number
                $serialNumber = $certInfo['serialNumber'] ?? null;
                $serialHex = $certInfo['serialNumberHex'] ?? null;

                if ($serialNumber || $serialHex) {
                    // Download CRL using openssl
                    $crlFile = tempnam(sys_get_temp_dir(), 'crl_');

                    // Use curl to download CRL
                    $ch = curl_init($crlUrl);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                    $crlData = curl_exec($ch);
                    $curlError = curl_errno($ch);
                    curl_close($ch);

                    if (!$curlError && $crlData) {
                        file_put_contents($crlFile, $crlData);

                        // Parse CRL and check for serial
                        $crlCommand = sprintf('openssl crl -in %s -inform DER -text -noout 2>&1', escapeshellarg($crlFile));
                        $crlOutput = shell_exec($crlCommand);

                        // If DER format fails, try PEM
                        if (stripos($crlOutput, 'error') !== false) {
                            $crlCommand = sprintf('openssl crl -in %s -inform PEM -text -noout 2>&1', escapeshellarg($crlFile));
                            $crlOutput = shell_exec($crlCommand);
                        }

                        @unlink($crlFile);

                        if ($crlOutput && stripos($crlOutput, 'error') === false) {
                            // Check if serial number is in CRL
                            $serialToFind = strtoupper($serialHex ?: dechex($serialNumber));
                            // Format serial for comparison (remove leading zeros, uppercase)
                            $serialToFind = ltrim($serialToFind, '0');

                            if (stripos($crlOutput, $serialToFind) !== false) {
                                $revocationStatus = 'revoked';
                                $chainStatus['issues'][] = "Certificate has been REVOKED (CRL check)";
                                $chainStatus['isValid'] = false;
                            } else {
                                $revocationStatus = 'crl_good';
                            }
                        } else {
                            $revocationStatus = 'crl_error';
                        }
                    } else {
                        $revocationStatus = 'crl_error';
                    }
                }
            } else if ($revocationStatus === 'no_ocsp') {
                $revocationStatus = 'no_revocation_info';
            }
        }
    }

    // Set overall validity and summary
    $hasHostnameIssue = !$hostnameInSan;
    if ($hasExpiredCert || $hasSelfSigned || $isIncompleteChain || $hasHostnameIssue) {
        $chainStatus['isValid'] = false;
        if ($hasSelfSigned) {
            $chainStatus['summary'] = "Self-signed certificate - not trusted by browsers";
        } elseif ($hasExpiredCert) {
            $chainStatus['summary'] = "Certificate chain contains expired certificate(s)";
        } elseif ($hasHostnameIssue) {
            $chainStatus['summary'] = "Hostname mismatch - certificate not valid for '{$hostname}'";
        } elseif ($isIncompleteChain) {
            $chainStatus['summary'] = "Incomplete certificate chain - missing intermediate certificate";
        }
    } else {
        $chainStatus['summary'] = "TLS Certificate is correctly installed";
    }

    // Add revocation status to chain status
    $chainStatus['revocationStatus'] = $revocationStatus;

    http_response_code(200);
    $responseData = [
        'chainStatus' => $chainStatus,
        'certificates' => $certificates
    ];

    // Include server header if available
    if (isset($serverHeader) && $serverHeader !== null) {
        $responseData['serverHeader'] = $serverHeader;
    }

    echo json_encode($responseData);

} catch (Exception $e) {
    send_error($e->getMessage(), is_int($e->getCode()) && $e->getCode() !== 0 ? $e->getCode() : 400);
}
