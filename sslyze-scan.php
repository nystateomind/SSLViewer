<?php
/**
 * SSLyze Vulnerability Scanner API
 *
 * This script runs sslyze against a specified host and port to perform
 * an enhanced security scan and returns the results as JSON.
 */

// Disable error display and start output buffering to ensure clean JSON
ini_set('display_errors', 0);
error_reporting(E_ALL);
ob_start();

// Set the content type to JSON for all responses
header("Content-Type: application/json");

/**
 * Sends a JSON error response and terminates the script.
 * @param string $message The error message.
 * @param int $statusCode The HTTP status code.
 */
function send_error($message, $statusCode = 400)
{
    // Clear any buffered output
    ob_end_clean();

    if (!headers_sent()) {
        header("Content-Type: application/json");
        http_response_code($statusCode);
    }
    echo json_encode(['error' => $message, 'success' => false]);
    exit;
}

/**
 * Sends a JSON success response.
 */
function send_json($data)
{
    // Clear any buffered output
    ob_end_clean();

    if (!headers_sent()) {
        header("Content-Type: application/json");
        http_response_code(200);
    }
    echo json_encode($data);
    exit;
}

// --- Custom Error Handlers ---
function json_error_handler($severity, $message, $file, $line)
{
    if (error_reporting() & $severity) {
        send_error("Server Error: " . basename($file) . " line $line", 500);
    }
    return true;
}
set_error_handler('json_error_handler');

function fatal_error_shutdown_handler()
{
    $last_error = error_get_last();
    if ($last_error && ($last_error['type'] === E_ERROR || $last_error['type'] === E_PARSE)) {
        send_error("Fatal Server Error: " . $last_error['message'], 500);
    }
}
register_shutdown_function('fatal_error_shutdown_handler');

// --- Main execution ---
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
    // Remove protocol prefixes and anything with *// pattern (e.g., https://, http://, *//, etc.)
    $hostname = preg_replace('/^.*\/\//', '', $hostname);
    $hostname = preg_replace('/[\/?#].*$/', '', $hostname);
    $hostname = preg_replace('/:\d+$/', '', $hostname);
    $hostname = trim($hostname);

    // Sanitize port input
    $port = isset($input['port']) ? (int) trim($input['port']) : 0;

    // Check if PostgreSQL mode
    $isPostgres = isset($input['isPostgres']) ? (bool) $input['isPostgres'] : false;

    // Check for wildcard hostname entry (e.g., *.domain.tld)
    if (strpos($hostname, '*.') === 0) {
        throw new Exception('To validate a wildcard certificate, enter a hostname it\'s installed on.');
    }

    if (empty($hostname) || filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new Exception('A valid hostname is required.');
    }

    if ($port <= 0 || $port > 65535) {
        throw new Exception('A valid port number (1-65535) is required.');
    }

    // Build the sslyze command with appropriate STARTTLS option
    $target = escapeshellarg("{$hostname}:{$port}");

    // Determine STARTTLS protocol based on port
    $starttlsOption = '';
    if ($isPostgres || $port === 5432) {
        $starttlsOption = '--starttls=postgres';
    } elseif ($port === 25 || $port === 587) {
        $starttlsOption = '--starttls=smtp';
    } elseif ($port === 21) {
        $starttlsOption = '--starttls=ftp';
    }
    if ($starttlsOption !== '') {
        $command = "sslyze --json_out=- {$starttlsOption} {$target} 2>&1";
    } else {
        $command = "sslyze --json_out=- {$target} 2>&1";
    }

    // Increase PHP execution time for this long-running scan
    set_time_limit(180); // 3 minutes

    // Execute sslyze using shell_exec (simpler, avoids pipe deadlock)
    $output = shell_exec($command);
    $errorOutput = ''; // stderr is redirected to stdout via 2>&1

    // Check if shell_exec failed completely
    if ($output === null || $output === false) {
        throw new Exception("Failed to execute SSLyze. Check if sslyze is installed and in the PATH.", 500);
    }

    // Trim output
    $output = trim($output);

    // Check if output is empty
    if (empty($output)) {
        throw new Exception("SSLyze returned empty output. Check if sslyze is working correctly.", 500);
    }

    // Check if sslyze is not available (check in output since stderr is redirected)
    if (strpos($output, 'not recognized') !== false || strpos($output, 'not found') !== false || strpos($output, 'is not recognized as') !== false) {
        throw new Exception("SSLyze is not installed or not in the system PATH.", 500);
    }

    // Check for connectivity errors BEFORE trying to parse JSON
    // Only flag as error if it's an actual connection failure, not JSON containing 'error' strings
    $isConnectionError = false;
    $errorMsg = '';
    $helpNote = '';

    // Check for specific connection failure patterns
    if (preg_match('/Could not connect|connection failed|Connection.*refused|timed out|CONNECTIVITY_ERROR_NO_CONNECTION/i', $output)) {
        $isConnectionError = true;
        if (stripos($output, 'Could not connect') !== false || stripos($output, 'CONNECTIVITY_ERROR') !== false) {
            $errorMsg = "Could not connect to {$hostname}:{$port}";
            $helpNote = "Verify the hostname and port are correct and the server is accessible.";
        } elseif (stripos($output, 'timed out') !== false) {
            $errorMsg = "Connection timed out for {$hostname}:{$port}";
            $helpNote = "Verify hostname and port are entered correctly and the application is running. The server may be behind a firewall.";
        } elseif (stripos($output, 'refused') !== false) {
            $errorMsg = "Connection refused by {$hostname}:{$port}";
            $helpNote = "The server actively refused the connection. Verify the port number and that the service is running.";
        } else {
            $errorMsg = "SSLyze connection failed for {$hostname}:{$port}";
            $helpNote = "Check network connectivity and verify the target is accessible.";
        }
    }

    if ($isConnectionError) {
        if ($helpNote) {
            $errorMsg .= " — " . $helpNote;
        }
        // Return as a valid JSON response with error details
        send_json([
            'success' => false,
            'error' => $errorMsg,
            'protocolSupport' => [],
            'securityChecks' => [],
            'vulnerabilities' => [],
            'cipherSuites' => [],
            'summary' => $errorMsg,
            'overallStatus' => 'ERROR'
        ]);
    }

    // Try to parse JSON output
    $jsonOutput = null;

    // SSLyze outputs JSON, try to extract it
    if (!empty($output)) {
        // Find the JSON portion of the output (look for first '{' and last '}')
        $jsonStart = strpos($output, '{');
        $jsonEnd = strrpos($output, '}');
        if ($jsonStart !== false && $jsonEnd !== false && $jsonEnd > $jsonStart) {
            $jsonString = substr($output, $jsonStart, $jsonEnd - $jsonStart + 1);
            $jsonOutput = json_decode($jsonString, true);

            // Check for JSON parse errors
            if (json_last_error() !== JSON_ERROR_NONE) {
                $jsonOutput = null;
            }
        }
    }

    if ($jsonOutput === null) {
        // If JSON parsing failed, return a structured error response
        send_json([
            'success' => false,
            'error' => 'Failed to parse SSLyze output',
            'protocolSupport' => [],
            'securityChecks' => [],
            'vulnerabilities' => [],
            'cipherSuites' => [],
            'summary' => 'SSLyze returned non-JSON output',
            'overallStatus' => 'ERROR'
        ]);
    } else {
        // Parse and format the SSLyze results
        $result = formatSslyzeResults($jsonOutput, $hostname, $port);
    }

    send_json($result);

} catch (Exception $e) {
    send_error($e->getMessage(), is_int($e->getCode()) && $e->getCode() !== 0 ? $e->getCode() : 400);
}

/**
 * Formats SSLyze JSON output into a more readable structure.
 * @param array $jsonOutput The parsed SSLyze JSON output.
 * @param string $hostname The target hostname.
 * @param int $port The target port.
 * @return array Formatted results.
 */
function formatSslyzeResults($jsonOutput, $hostname, $port)
{
    $result = [
        'success' => true,
        'target' => "{$hostname}:{$port}",
        'scanDate' => date('Y-m-d H:i:s'),
        'protocolSupport' => [],
        'vulnerabilities' => [],
        'cipherSuites' => [],
        'certificateInfo' => null
    ];

    // Check if we have server scan results
    if (!isset($jsonOutput['server_scan_results']) || empty($jsonOutput['server_scan_results'])) {
        $result['success'] = false;
        $result['error'] = 'No scan results returned from SSLyze';
        return $result;
    }

    $scanResult = $jsonOutput['server_scan_results'][0] ?? null;
    if (!$scanResult) {
        return $result;
    }

    $commands = $scanResult['scan_result'] ?? [];

    // Protocol Support - All SSL/TLS versions
    // SSLyze uses keys like 'ssl_2_0_cipher_suites', 'tls_1_3_cipher_suites'
    $protocols = [
        'ssl_2_0_cipher_suites' => ['name' => 'SSL 2.0', 'deprecated' => true],
        'ssl_3_0_cipher_suites' => ['name' => 'SSL 3.0', 'deprecated' => true],
        'tls_1_0_cipher_suites' => ['name' => 'TLS 1.0', 'deprecated' => true],
        'tls_1_1_cipher_suites' => ['name' => 'TLS 1.1', 'deprecated' => true],
        'tls_1_2_cipher_suites' => ['name' => 'TLS 1.2', 'deprecated' => false],
        'tls_1_3_cipher_suites' => ['name' => 'TLS 1.3', 'deprecated' => false]
    ];

    foreach ($protocols as $key => $proto) {
        $name = $proto['name'];
        $isDeprecated = $proto['deprecated'];

        if (isset($commands[$key])) {
            $protoResult = $commands[$key]['result'] ?? null;
            if ($protoResult) {
                // Check both is_tls_version_supported and accepted_cipher_suites
                $isSupported = isset($protoResult['is_tls_version_supported'])
                    ? $protoResult['is_tls_version_supported']
                    : !empty($protoResult['accepted_cipher_suites'] ?? []);
                $accepted = $protoResult['accepted_cipher_suites'] ?? [];

                // Extract cipher names
                $cipherNames = [];
                foreach ($accepted as $cipher) {
                    if (isset($cipher['cipher_suite']['name'])) {
                        $cipherNames[] = $cipher['cipher_suite']['name'];
                    }
                }

                $result['protocolSupport'][] = [
                    'protocol' => $name,
                    'supported' => $isSupported,
                    'deprecated' => $isDeprecated,
                    'cipherCount' => count($accepted),
                    'ciphers' => $cipherNames,
                    'checked' => true
                ];

                // Add deprecation warning
                if ($isSupported && $isDeprecated) {
                    $result['vulnerabilities'][] = [
                        'name' => "Deprecated Protocol: {$name}",
                        'severity' => ($key === 'ssl_2_0_cipher_suites' || $key === 'ssl_3_0_cipher_suites') ? 'HIGH' : 'MEDIUM',
                        'description' => "{$name} is deprecated and should be disabled."
                    ];
                }
            } else {
                // Result exists but no data
                $result['protocolSupport'][] = [
                    'protocol' => $name,
                    'supported' => false,
                    'deprecated' => $isDeprecated,
                    'cipherCount' => 0,
                    'checked' => true
                ];
            }
        } else {
            // Protocol wasn't checked
            $result['protocolSupport'][] = [
                'protocol' => $name,
                'supported' => false,
                'deprecated' => $isDeprecated,
                'cipherCount' => 0,
                'checked' => false
            ];
        }
    }

    // Vulnerability Checks - track both passed and failed
    $securityChecks = [];

    // Heartbleed check
    if (isset($commands['heartbleed']['result'])) {
        $vulnResult = $commands['heartbleed']['result'];
        $isVulnerable = isset($vulnResult['is_vulnerable_to_heartbleed']) && $vulnResult['is_vulnerable_to_heartbleed'];
        $securityChecks[] = [
            'name' => 'Heartbleed (CVE-2014-0160)',
            'passed' => !$isVulnerable,
            'severity' => 'CRITICAL',
            'description' => $isVulnerable ? 'Server is vulnerable to the Heartbleed bug.' : 'Server is not vulnerable to Heartbleed.'
        ];
        if ($isVulnerable) {
            $result['vulnerabilities'][] = [
                'name' => 'Heartbleed (CVE-2014-0160)',
                'severity' => 'CRITICAL',
                'description' => 'Server is vulnerable to the Heartbleed bug.'
            ];
        }
    }

    // OpenSSL CCS Injection check
    if (isset($commands['openssl_ccs_injection']['result'])) {
        $vulnResult = $commands['openssl_ccs_injection']['result'];
        $isVulnerable = isset($vulnResult['is_vulnerable_to_ccs_injection']) && $vulnResult['is_vulnerable_to_ccs_injection'];
        $securityChecks[] = [
            'name' => 'OpenSSL CCS Injection (CVE-2014-0224)',
            'passed' => !$isVulnerable,
            'severity' => 'HIGH',
            'description' => $isVulnerable ? 'Server is vulnerable to CCS injection attack.' : 'Server is not vulnerable to CCS injection.'
        ];
        if ($isVulnerable) {
            $result['vulnerabilities'][] = [
                'name' => 'OpenSSL CCS Injection (CVE-2014-0224)',
                'severity' => 'HIGH',
                'description' => 'Server is vulnerable to OpenSSL CCS injection attack.'
            ];
        }
    }

    // Secure Renegotiation check
    if (isset($commands['session_renegotiation']['result'])) {
        $vulnResult = $commands['session_renegotiation']['result'];
        $supportsSecure = isset($vulnResult['supports_secure_renegotiation']) && $vulnResult['supports_secure_renegotiation'];
        $securityChecks[] = [
            'name' => 'Secure Renegotiation',
            'passed' => $supportsSecure,
            'severity' => 'MEDIUM',
            'description' => $supportsSecure ? 'Server supports secure renegotiation.' : 'Server does not support secure renegotiation.'
        ];
        if (!$supportsSecure) {
            $result['vulnerabilities'][] = [
                'name' => 'Insecure Renegotiation',
                'severity' => 'MEDIUM',
                'description' => 'Server does not support secure renegotiation.'
            ];
        }
    }

    // Add security checks to result
    $result['securityChecks'] = $securityChecks;

    // TLS 1.2 Cipher Suites (sample)
    if (isset($commands['tls_1_2']['result']['accepted_cipher_suites'])) {
        $ciphers = $commands['tls_1_2']['result']['accepted_cipher_suites'];
        foreach (array_slice($ciphers, 0, 10) as $cipher) {
            $cipherName = $cipher['cipher_suite']['name'] ?? 'Unknown';
            $keySize = $cipher['cipher_suite']['key_size'] ?? 0;

            $result['cipherSuites'][] = [
                'name' => $cipherName,
                'keySize' => $keySize,
                'protocol' => 'TLS 1.2'
            ];
        }
    }

    // TLS 1.3 Cipher Suites
    if (isset($commands['tls_1_3']['result']['accepted_cipher_suites'])) {
        $ciphers = $commands['tls_1_3']['result']['accepted_cipher_suites'];
        foreach ($ciphers as $cipher) {
            $cipherName = $cipher['cipher_suite']['name'] ?? 'Unknown';

            $result['cipherSuites'][] = [
                'name' => $cipherName,
                'keySize' => 256,
                'protocol' => 'TLS 1.3'
            ];
        }
    }

    // Add summary
    $vulnCount = count($result['vulnerabilities']);
    if ($vulnCount === 0) {
        $result['summary'] = 'No known vulnerabilities detected.';
        $result['overallStatus'] = 'PASS';
    } else {
        $criticalCount = count(array_filter($result['vulnerabilities'], fn($v) => $v['severity'] === 'CRITICAL'));
        $highCount = count(array_filter($result['vulnerabilities'], fn($v) => $v['severity'] === 'HIGH'));

        if ($criticalCount > 0) {
            $result['overallStatus'] = 'CRITICAL';
            $result['summary'] = "{$criticalCount} critical and {$highCount} high severity issues found.";
        } elseif ($highCount > 0) {
            $result['overallStatus'] = 'WARNING';
            $result['summary'] = "{$highCount} high/medium severity issues found.";
        } else {
            $result['overallStatus'] = 'INFO';
            $result['summary'] = "{$vulnCount} minor issues found.";
        }
    }

    return $result;
}
