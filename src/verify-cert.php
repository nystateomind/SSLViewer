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

// Set PHP execution time limit as failsafe (30 seconds max)
set_time_limit(20);

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
        // DEBUG: Show actual error for troubleshooting (remove in production)
        send_error("Server Error: {$message} in {$file} on line {$line}", 500);
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
        // Deduplicate certs by normalizing content (openssl s_client often outputs leaf cert twice)
        $seen = [];
        foreach ($matches[1] as $cert) {
            // Normalize by removing all whitespace to compare actual content
            $normalized = preg_replace('/\s+/', '', $cert);
            if (!isset($seen[$normalized])) {
                $seen[$normalized] = true;
                $certs[] = $cert;
            }
        }
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

/**
 * Resolves all A and AAAA DNS records for a hostname.
 * @param string $hostname The hostname to resolve.
 * @return array Associative array with 'A' and 'AAAA' record arrays.
 */
function get_dns_records($hostname)
{
    $records = ['A' => [], 'AAAA' => []];
    $aRecords = @dns_get_record($hostname, DNS_A);
    $aaaaRecords = @dns_get_record($hostname, DNS_AAAA);
    if ($aRecords) {
        foreach ($aRecords as $r) {
            $records['A'][] = $r['ip'];
        }
    }
    if ($aaaaRecords) {
        foreach ($aaaaRecords as $r) {
            $records['AAAA'][] = $r['ipv6'];
        }
    }
    return $records;
}

/**
 * Checks revocation status of a certificate using OCSP and CRL.
 * @param string $certPem The PEM-encoded certificate (for temp file creation).
 * @param array $certInfo The parsed certificate info from openssl_x509_parse().
 * @param string|null $issuerPem The PEM-encoded issuer certificate (required for OCSP).
 * @return array ['status' => string, 'method' => string|null] - status and method used (ocsp/crl)
 */
function check_cert_revocation($certPem, $certInfo, $issuerPem = null)
{
    $revocationStatus = 'unknown';
    $method = null;

    if (!$certInfo) {
        return ['status' => 'error', 'method' => null];
    }

    // Skip revocation check for self-signed/root certificates
    if ($certInfo['subject'] === $certInfo['issuer']) {
        return ['status' => 'not_applicable', 'method' => null];
    }

    // --- OCSP Check (requires issuer cert) ---
    if ($issuerPem) {
        $ocspUrl = null;
        if (isset($certInfo['extensions']['authorityInfoAccess'])) {
            if (preg_match('/OCSP\s*-\s*URI:(\S+)/i', $certInfo['extensions']['authorityInfoAccess'], $matches)) {
                $ocspUrl = $matches[1];
            }
        }

        if ($ocspUrl) {
            $leafFile = tempnam(sys_get_temp_dir(), 'cert_');
            $issuerFile = tempnam(sys_get_temp_dir(), 'issuer_');

            file_put_contents($leafFile, $certPem);
            file_put_contents($issuerFile, $issuerPem);

            $ocspCommand = sprintf(
                'openssl ocsp -issuer %s -cert %s -url %s -no_nonce 2>&1',
                escapeshellarg($issuerFile),
                escapeshellarg($leafFile),
                escapeshellarg($ocspUrl)
            );

            $ocspOutput = shell_exec($ocspCommand);

            @unlink($leafFile);
            @unlink($issuerFile);

            if ($ocspOutput !== null) {
                if (stripos($ocspOutput, ': good') !== false) {
                    return ['status' => 'good', 'method' => 'ocsp'];
                } elseif (stripos($ocspOutput, ': revoked') !== false) {
                    return ['status' => 'revoked', 'method' => 'ocsp'];
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
    } else {
        // No issuer available, check if OCSP URL exists
        if (
            isset($certInfo['extensions']['authorityInfoAccess']) &&
            stripos($certInfo['extensions']['authorityInfoAccess'], 'OCSP') !== false
        ) {
            $revocationStatus = 'ocsp_available';
        } else {
            $revocationStatus = 'no_ocsp';
        }
    }

    // --- CRL Fallback if OCSP failed or not available ---
    if (in_array($revocationStatus, ['no_ocsp', 'ocsp_error', 'ocsp_unknown', 'error', 'unknown'])) {
        $crlUrl = null;
        if (isset($certInfo['extensions']['crlDistributionPoints'])) {
            if (preg_match('/URI:(\S+)/i', $certInfo['extensions']['crlDistributionPoints'], $matches)) {
                $crlUrl = $matches[1];
            }
        }

        if ($crlUrl) {
            $serialNumber = $certInfo['serialNumber'] ?? null;
            $serialHex = $certInfo['serialNumberHex'] ?? null;

            if ($serialNumber || $serialHex) {
                $crlFile = tempnam(sys_get_temp_dir(), 'crl_');

                $ch = curl_init($crlUrl);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                $crlData = curl_exec($ch);
                $curlError = curl_errno($ch);

                if (!$curlError && $crlData) {
                    file_put_contents($crlFile, $crlData);

                    $crlCommand = sprintf('openssl crl -in %s -inform DER -text -noout 2>&1', escapeshellarg($crlFile));
                    $crlOutput = shell_exec($crlCommand);

                    if (stripos($crlOutput, 'error') !== false) {
                        $crlCommand = sprintf('openssl crl -in %s -inform PEM -text -noout 2>&1', escapeshellarg($crlFile));
                        $crlOutput = shell_exec($crlCommand);
                    }

                    @unlink($crlFile);

                    if ($crlOutput && stripos($crlOutput, 'error') === false) {
                        $serialToFind = strtoupper($serialHex ?: dechex($serialNumber));
                        $serialToFind = ltrim($serialToFind, '0');

                        if (stripos($crlOutput, $serialToFind) !== false) {
                            return ['status' => 'revoked', 'method' => 'crl'];
                        } else {
                            return ['status' => 'crl_good', 'method' => 'crl'];
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

    return ['status' => $revocationStatus, 'method' => $method];
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
    $connectedIp = null;

    // Determine if we need STARTTLS for specific protocols
    $starttlsProtocol = null;
    if ($port === 5432) {
        $starttlsProtocol = 'postgres';
    } elseif ($port === 25 || $port === 587 || $port === 25587) {
        $starttlsProtocol = 'smtp';
    } elseif ($port === 21) {
        $starttlsProtocol = 'ftp';
    }

    if ($starttlsProtocol !== null) {
        // --- Check for Legacy Renegotiation Support ---
        $helpOutput = shell_exec('openssl s_client -help 2>&1');
        $legacyFlag = (strpos($helpOutput, '-legacy_renegotiation') !== false) ? ' -legacy_renegotiation' : '';

        // --- Use OpenSSL for services with STARTTLS ---
        $command = "openssl s_client{$legacyFlag} -starttls {$starttlsProtocol} -showcerts -connect " . escapeshellarg("$hostname:$port");

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

        // Set streams to non-blocking for proper timeout handling
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $output = '';
        $error_output = '';
        $timeout = 10; // 10 second timeout
        $startTime = time();

        // Poll streams with timeout
        while (true) {
            $read = [$pipes[1], $pipes[2]];
            $write = null;
            $except = null;

            // Check if process is still running
            $status = proc_get_status($process);

            // Use stream_select with 1 second timeout for polling
            $ready = @stream_select($read, $write, $except, 1);

            if ($ready === false) {
                // stream_select error
                break;
            }

            foreach ($read as $stream) {
                $data = fread($stream, 8192);
                if ($stream === $pipes[1]) {
                    $output .= $data;
                } else {
                    $error_output .= $data;
                }
            }

            // Check timeout
            if ((time() - $startTime) >= $timeout) {
                proc_terminate($process);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                throw new Exception("Connection timed out while performing STARTTLS (10 second limit).", 500);
            }

            // If process ended and no more data, exit
            if (!$status['running'] && feof($pipes[1]) && feof($pipes[2])) {
                break;
            }
        }

        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        if (empty($output) && !empty($error_output)) {
            throw new Exception("OpenSSL command failed. Verify hostname and port are correct.", 500);
        }

        if (strpos($output, '-----BEGIN CERTIFICATE-----') === false) {
            // Check for specific OpenSSL errors like legacy renegotiation
            if (strpos($error_output, 'unsafe legacy renegotiation disabled') !== false) {
                throw new Exception("Connection failed: Unsafe legacy renegotiation disabled. This server is likely insecure.", 500);
            }
            throw new Exception("Failed to connect or perform STARTTLS.", 500);
        }

        $rawCerts = parse_pem_certs($output);
        if (empty($rawCerts)) {
            throw new Exception("Connected, but could not parse a valid certificate from the output.", 500);
        }

        // Extract connected IP from OpenSSL output (format: "Connecting to X.X.X.X")
        if (preg_match('/^Connecting to ([0-9a-f.:]+)/mi', $error_output, $ipMatches)) {
            $connectedIp = $ipMatches[1];
        }

    } else {
        // --- Use cURL for standard HTTPS ---
        if (!function_exists('curl_init')) {
            throw new Exception('The cURL extension is not installed or enabled on this server.', 500);
        }
        $ch = curl_init();
        $headers = ''; // Initialize to prevent undefined variable error
        curl_setopt($ch, CURLOPT_URL, "https://{$hostname}:{$port}");
        curl_setopt($ch, CURLOPT_PORT, $port);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
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
        $curlErrno = curl_errno($ch);
        $curlError = curl_error($ch);

        // Fallback to OpenSSL CLI if cURL fails for ANY reason
        if ($response === false) {
            // Fallback to OpenSSL CLI
            $helpOutput = shell_exec('openssl s_client -help 2>&1');
            $legacyFlag = (strpos($helpOutput, '-legacy_renegotiation') !== false) ? ' -legacy_renegotiation' : '';

            // Use openssl s_client to fetch certs
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $cmd = sprintf(
                    'cmd /c "openssl s_client%s -showcerts -connect %s < NUL 2>&1"',
                    $legacyFlag,
                    trim(escapeshellarg("$hostname:$port"), "'\"")
                );
            } else {
                $cmd = "openssl s_client{$legacyFlag} -showcerts -connect " . escapeshellarg("$hostname:$port") . " < /dev/null 2>&1";
            }

            $opensslOutput = shell_exec($cmd);
            if ($opensslOutput && strpos($opensslOutput, '-----BEGIN CERTIFICATE-----') !== false) {
                // Success fallback!
                $response = $opensslOutput; // Treat output as response for cert parsing
                // Parse PEMs directly from OpenSSL output
                $fallbackCerts = parse_pem_certs($opensslOutput);
                if (!empty($fallbackCerts)) {
                    $rawCerts = $fallbackCerts;
                    $certChainInfo = []; // Prevent curl_getinfo from overriding fallback certs
                }

                // Extract connected IP from OpenSSL output (format: "Connecting to X.X.X.X")
                if (preg_match('/^Connecting to ([0-9a-f.:]+)/mi', $opensslOutput, $ipMatches)) {
                    $connectedIp = $ipMatches[1];
                } else {
                    // Fallback to DNS lookup
                    $connectedIp = gethostbyname($hostname);
                    if ($connectedIp === $hostname) {
                        $connectedIp = null; // DNS lookup failed
                    }
                }

                // Run enterprise detection if we have an IP
                $serverHeader = null;
                if ($connectedIp && function_exists('enterprise_detect_infrastructure')) {
                    $detected = enterprise_detect_infrastructure($hostname, $connectedIp, '');
                    if ($detected) {
                        $serverHeader = $detected;
                    }
                }

                // We lose HTTP headers, but we can still detect infrastructure
                // Mock headers to avoid downstream errors
                $mockServerValue = $serverHeader ?? 'Unknown (Fallback)';
                $headers = "HTTP/1.1 200 OK\r\nServer: {$mockServerValue}\r\n\r\n";
                $headerSize = strlen($headers);
                $response = $headers . $opensslOutput; // Prepend headers
            }
        }

        if ($response !== false && !isset($certChainInfo)) {
            $certChainInfo = curl_getinfo($ch, CURLINFO_CERTINFO);
            $connectedIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $headers = substr($response, 0, $headerSize);
        }

        // Extract Server header and detect CDN/WAF
        $serverHeader = null;
        if (isset($headers) && preg_match('/^Server:\h*(.*)$/mi', $headers, $matches)) {
            $serverHeader = trim($matches[1]);
        }

        // Detect CDN/WAF from headers when Server header is missing or generic
        $cdnDetected = null;

        // Enterprise-specific detection (runs FIRST, uses DNS lookup for IP-based detection)
        if (function_exists('enterprise_detect_infrastructure')) {
            $ipAddress = gethostbyname($hostname);
            if (isset($headers)) {
                $cdnDetected = enterprise_detect_infrastructure($hostname, $ipAddress, $headers);
            }
        }

        // Generic detection using combined regex patterns (only if enterprise didn't match)
        if ($cdnDetected === null) {
            // CDN/WAF detection patterns
            $cdnPatterns = [
                'Akamai' => '/^(X-Akamai-|Akamai-|X-True-Cache-Key:|X-Cache:.*(?:akamaitechnologies\.com|AkamaiGHost))/mi',
                'Cloudflare' => '/^(CF-RAY:|CF-Cache-Status:|Server:\s*cloudflare)/mi',
                'Fastly' => '/^(X-Served-By:.*cache|Fastly-|X-Fastly-)/mi',
                'AWS CloudFront' => '/^(X-Amz-Cf-Id:|X-Amz-Cf-Pop:|Via:.*CloudFront)/mi',
                'AWS API Gateway' => '/^(x-amz-apigw-id:|x-amzn-requestid:|x-amzn-errortype:|x-amzn-errormessage:)/mi',
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
                'Microsoft IIS' => '/^(X-Powered-By:\s*(?:ASP\.NET|ARR)|X-AspNet-Version:|X-AspNetMvc-Version:|Set-Cookie:\s*(?:ASP\.NET_SessionId|ASPSESSIONID)|X-FEServer:|X-BEServer:|X-CalculatedBETarget:|X-SharePointHealthScore:|SPIisLatency:|SPRequestGuid:|X-DiagInfo:|X-MS-InvokeApp:|X-UA-Compatible:)/mi',
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
        $genericSignatures = ['akamaighost', 'apache', 'nginx', 'microsoft-iis', 'server', 'awselb', 'cloudflare'];
        $isGeneric = false;

        if (empty($serverHeader)) {
            $isGeneric = true;
        } else {
            $lowerServer = strtolower($serverHeader);
            if (in_array($lowerServer, $genericSignatures)) {
                $isGeneric = true;
            } else {
                // Check if it starts with any generic signature (e.g. "apache/2.4")
                foreach ($genericSignatures as $sig) {
                    if (strpos($lowerServer, $sig) === 0) {
                        $isGeneric = true;
                    } else {
                        // Check if it starts with any generic signature (e.g. "apache/2.4")
                        foreach ($genericSignatures as $sig) {
                            if (strpos($lowerServer, $sig) === 0) {
                                $isGeneric = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if ($cdnDetected && $isGeneric) {
            $serverHeader = $cdnDetected . ($serverHeader ? ' (' . $serverHeader . ')' : '');
        }

        if (curl_errno($ch)) {
            if (empty($certChainInfo) && empty($rawCerts)) { // Only throw error if we don't have certs from fallback
                $curlError = curl_error($ch);
                $curlErrno = curl_errno($ch);

                // Provide helpful message for timeout errors (CURLE_OPERATION_TIMEDOUT = 28)
                if ($curlErrno === 28 || stripos($curlError, 'timed out') !== false) {
                    throw new Exception(
                        "Connection timed out. Verify that an SSL/TLS service is running on <strong>{$hostname}:{$port}</strong>.",
                        500
                    );
                }

                // Provide helpful message for connection refused (CURLE_COULDNT_CONNECT = 7)
                if ($curlErrno === 7 || stripos($curlError, 'refused') !== false) {
                    throw new Exception(
                        "Connection refused. Verify that a service is running on <strong>{$hostname}:{$port}</strong>.",
                        500
                    );
                }

                throw new Exception('Connection error: ' . $curlError, 500);
            }
        }
        // curl_close() removed - not needed in PHP 8.0+, handles auto-close

        if (empty($rawCerts) && !empty($certChainInfo)) {
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

        $subjectOValue = $certInfo['subject']['O'] ?? 'N/A';
        $subjectO = is_array($subjectOValue) ? implode(', ', $subjectOValue) : $subjectOValue;

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
            'organization' => $subjectO,
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
        // Note: Summary message is set below based on this flag, no need to add to issues array
    }

    // --- Revocation Check for ALL certificates in chain ---
    $revocationChecks = [];
    $hasRevokedCert = false;
    $overallRevocationStatus = 'unknown';

    // Build a lookup of parsed cert info for each raw cert (to pass to revocation check)
    $parsedCertInfo = [];
    foreach ($rawCerts as $idx => $pem) {
        $res = openssl_x509_read($pem);
        $parsedCertInfo[$idx] = $res ? openssl_x509_parse($res) : null;
    }

    foreach ($certificates as $index => $cert) {
        // Get issuer cert PEM (next in chain) if available
        $issuerPem = isset($rawCerts[$index + 1]) ? $rawCerts[$index + 1] : null;
        $certPem = $rawCerts[$index];
        $certInfo = $parsedCertInfo[$index];

        // Check revocation status using already-parsed cert info
        $result = check_cert_revocation($certPem, $certInfo, $issuerPem);
        $status = $result['status'];
        $method = $result['method'];

        $revocationChecks[] = [
            'index' => $index,
            'commonName' => $cert['commonName'],
            'status' => $status,
            'method' => $method
        ];

        // Track if any certificate is revoked
        if ($status === 'revoked') {
            $hasRevokedCert = true;
            $chainStatus['issues'][] = "Certificate has been REVOKED";
            $chainStatus['isValid'] = false;
        }

        // Set overall status (use first definitive status found)
        if ($overallRevocationStatus === 'unknown') {
            if (in_array($status, ['good', 'crl_good', 'revoked'])) {
                $overallRevocationStatus = $status;
            }
        }
        // Revoked takes precedence over everything
        if ($status === 'revoked') {
            $overallRevocationStatus = 'revoked';
        }
    }

    // If no definitive status found, use the leaf cert's status
    if ($overallRevocationStatus === 'unknown' && !empty($revocationChecks)) {
        $overallRevocationStatus = $revocationChecks[0]['status'];
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
    $chainStatus['revocationStatus'] = $overallRevocationStatus;
    $chainStatus['revocationChecks'] = $revocationChecks;

    http_response_code(200);
    $responseData = [
        'chainStatus' => $chainStatus,
        'certificates' => $certificates
    ];

    // Include server header if available
    if (isset($serverHeader) && $serverHeader !== null) {
        $responseData['serverHeader'] = $serverHeader;
    }

    // Include connection info (connected IP and DNS records)
    $responseData['connectionInfo'] = [
        'connectedIp' => $connectedIp,
        'dnsRecords' => get_dns_records($hostname)
    ];

    echo json_encode($responseData);

} catch (Exception $e) {
    send_error($e->getMessage(), is_int($e->getCode()) && $e->getCode() !== 0 ? $e->getCode() : 400);
}
