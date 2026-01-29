<?php
/**
 * PQC (Post-Quantum Cryptography) Key Exchange Detection
 * 
 * This script tests whether a server supports post-quantum key exchange
 * algorithms (ML-KEM/CRYSTALS-Kyber) in TLS 1.3 using OpenSSL s_client.
 */

/**
 * Starts PQC detection asynchronously (non-blocking).
 * Returns a process handle that can be polled later.
 * 
 * @param string $hostname The target hostname
 * @param int $port The target port
 * @return array Process info with handle, pipes, and start time
 */
function startPqcScanAsync($hostname, $port)
{
    $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

    // Build command to test the most common PQC group first
    // X25519MLKEM768 is the NIST standardized hybrid
    $group = 'X25519MLKEM768';

    if ($isWindows) {
        // Windows: use cmd /c with stdin redirected from NUL for EOF
        $command = sprintf(
            'cmd /c "openssl s_client -connect %s:%d -tls1_3 -groups %s < NUL 2>&1"',
            escapeshellarg($hostname),
            (int) $port,
            $group
        );
    } else {
        // Linux: Use OpenSSL 3.5+ at /usr/local/ssl/bin for PQC support
        // (system OpenSSL 3.0 doesn't support PQC groups)
        $opensslBin = file_exists('/usr/local/ssl/bin/openssl')
            ? '/usr/local/ssl/bin/openssl'
            : 'openssl';
        $command = sprintf(
            'timeout 5 %s s_client -connect %s:%d -tls1_3 -groups %s < /dev/null 2>&1',
            $opensslBin,
            escapeshellarg($hostname),
            (int) $port,
            escapeshellarg($group)
        );
    }

    $descriptorSpec = [
        0 => ['pipe', 'r'],  // stdin
        1 => ['pipe', 'w'],  // stdout
        2 => ['pipe', 'w'],  // stderr
    ];

    $process = proc_open($command, $descriptorSpec, $pipes);

    if (!is_resource($process)) {
        return [
            'success' => false,
            'error' => 'Failed to start PQC detection process'
        ];
    }

    // Close stdin immediately
    fclose($pipes[0]);

    // Set stdout to non-blocking for polling
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    return [
        'success' => true,
        'process' => $process,
        'stdout' => $pipes[1],
        'stderr' => $pipes[2],
        'startTime' => microtime(true),
        'group' => $group,
        'hostname' => $hostname,
        'port' => $port
    ];
}

/**
 * Collects the result from an async PQC scan.
 * 
 * @param array $processInfo The process info from startPqcScanAsync
 * @param float $maxWaitSeconds Maximum seconds to wait for result (0 = don't wait)
 * @return array PQC detection result
 */
function collectPqcResult($processInfo, $maxWaitSeconds = 0)
{
    $result = [
        'pqcSupported' => false,
        'negotiatedGroup' => null,
        'testedGroups' => [],
        'error' => null
    ];

    if (!$processInfo['success']) {
        $result['error'] = $processInfo['error'] ?? 'PQC scan failed to start';
        return $result;
    }

    $process = $processInfo['process'];
    $stdout = $processInfo['stdout'];
    $stderr = $processInfo['stderr'];
    $group = $processInfo['group'];

    $output = '';
    $startWait = microtime(true);

    // Wait for process to complete (with timeout)
    while (true) {
        $status = proc_get_status($process);

        // Read available output
        $output .= stream_get_contents($stdout);

        if (!$status['running']) {
            // Process finished - get remaining output
            $output .= stream_get_contents($stdout);
            break;
        }

        // Check timeout
        if ($maxWaitSeconds > 0 && (microtime(true) - $startWait) >= $maxWaitSeconds) {
            // Timeout - assume no PQC support (SSLyze finished first)
            proc_terminate($process);
            fclose($stdout);
            fclose($stderr);
            proc_close($process);

            $result['testedGroups'][] = [
                'group' => $group,
                'supported' => false,
                'error' => 'Scan timeout - SSLyze completed first'
            ];
            return $result;
        }

        // Small sleep to prevent CPU spinning
        usleep(50000); // 50ms
    }

    // Clean up
    fclose($stdout);
    fclose($stderr);
    proc_close($process);

    // Parse output for PQC indicators
    $testResult = parsePqcOutput($output, $group);
    $result['testedGroups'][] = [
        'group' => $group,
        'supported' => $testResult['supported'],
        'error' => $testResult['error'] ?? null
    ];

    if ($testResult['supported']) {
        $result['pqcSupported'] = true;
        $result['negotiatedGroup'] = $testResult['negotiatedGroup'] ?? $group;
    }

    return $result;
}

/**
 * Parses OpenSSL s_client output for PQC indicators.
 * 
 * @param string $output The command output
 * @param string $group The tested group
 * @return array Result with 'supported' and optional 'negotiatedGroup'
 */
function parsePqcOutput($output, $group)
{
    $result = [
        'supported' => false,
        'negotiatedGroup' => null,
        'error' => null
    ];

    // Pattern 0: "Negotiated TLS1.3 group:" - Modern OpenSSL 3.x format
    if (preg_match('/Negotiated TLS1\.3 group:\s*([^\r\n]+)/i', $output, $matches)) {
        $negotiatedGroup = trim($matches[1]);

        if (preg_match('/(MLKEM|Kyber|ML-KEM)/i', $negotiatedGroup)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $negotiatedGroup;
            return $result;
        }
    }

    // Pattern 1: "Server Temp Key:" - older OpenSSL
    if (preg_match('/Server Temp Key:\s*([^\r\n]+)/i', $output, $matches)) {
        $tempKey = trim($matches[1]);

        if (preg_match('/(MLKEM|Kyber|X25519MLKEM|X25519Kyber|ML-KEM)/i', $tempKey)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $tempKey;
            return $result;
        }
    }

    // Check for connection errors
    if (preg_match('/connect:errno|Connection refused|Connection timed out/i', $output)) {
        $result['error'] = 'Connection failed';
    } elseif (preg_match('/no protocols available|wrong version number/i', $output)) {
        $result['error'] = 'TLS 1.3 not supported';
    }

    return $result;
}

/**
 * Detects PQC key exchange support for a given host (synchronous version).
 * 
 * @param string $hostname The target hostname
 * @param int $port The target port
 * @return array PQC detection results
 */
function detectPqcSupport($hostname, $port)
{
    $result = [
        'pqcSupported' => false,
        'negotiatedGroup' => null,
        'testedGroups' => [],
        'error' => null
    ];

    // PQC groups to test (in order of preference)
    // X25519MLKEM768 is the NIST standardized hybrid
    // X25519Kyber768Draft00 is the draft/legacy version some servers still use
    $pqcGroups = [
        'X25519MLKEM768',
        'X25519Kyber768Draft00',
        'mlkem768',
        'kyber768'
    ];

    // Check if openssl supports the -groups option
    $helpOutput = shell_exec('openssl s_client -help 2>&1');
    if ($helpOutput === null || strpos($helpOutput, '-groups') === false) {
        $result['error'] = 'OpenSSL does not support -groups option. PQC detection requires OpenSSL 3.0+';
        return $result;
    }

    // Test each PQC group
    foreach ($pqcGroups as $group) {
        $testResult = testPqcGroup($hostname, $port, $group);
        $result['testedGroups'][] = [
            'group' => $group,
            'supported' => $testResult['supported'],
            'error' => $testResult['error'] ?? null
        ];

        if ($testResult['supported']) {
            $result['pqcSupported'] = true;
            $result['negotiatedGroup'] = $testResult['negotiatedGroup'] ?? $group;
            // Found PQC support, no need to test other groups
            break;
        }
    }

    return $result;
}

/**
 * Tests a specific PQC group against a server.
 * 
 * @param string $hostname The target hostname
 * @param int $port The target port
 * @param string $group The PQC group to test
 * @return array Test result with 'supported' boolean and optional 'negotiatedGroup'
 */
function testPqcGroup($hostname, $port, $group)
{
    $result = [
        'supported' => false,
        'negotiatedGroup' => null,
        'error' => null
    ];

    // Build the OpenSSL command
    $escapedHost = escapeshellarg($hostname);
    $escapedGroup = escapeshellarg($group);

    // Detect OS for cross-platform compatibility
    $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

    if ($isWindows) {
        // Windows: use cmd /c with stdin redirected from NUL for EOF
        $command = sprintf(
            'cmd /c "openssl s_client -connect %s:%d -tls1_3 -groups %s < NUL 2>&1"',
            trim($escapedHost, "'\""),
            (int) $port,
            trim($escapedGroup, "'\"")
        );
    } else {
        // Linux: Use OpenSSL 3.5+ at /usr/local/ssl/bin for PQC support
        $opensslBin = file_exists('/usr/local/ssl/bin/openssl')
            ? '/usr/local/ssl/bin/openssl'
            : 'openssl';
        $command = sprintf(
            'timeout 5 %s s_client -connect %s:%d -tls1_3 -groups %s < /dev/null 2>&1',
            $opensslBin,
            $escapedHost,
            (int) $port,
            $escapedGroup
        );
    }

    $output = shell_exec($command);

    if ($output === null) {
        $result['error'] = 'Failed to execute OpenSSL command';
        return $result;
    }

    // Check for successful TLS 1.3 connection with PQC
    // Look for indicators in the output that PQC was negotiated

    // Pattern 0: "Negotiated TLS1.3 group:" - Modern OpenSSL 3.x format
    if (preg_match('/Negotiated TLS1\.3 group:\s*([^\r\n]+)/i', $output, $matches)) {
        $negotiatedGroup = trim($matches[1]);

        // Check if it's a PQC/hybrid group
        if (preg_match('/(MLKEM|Kyber|ML-KEM)/i', $negotiatedGroup)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $negotiatedGroup;
            return $result;
        }
    }

    // Pattern 1: "Server Temp Key:" line showing the key exchange (older OpenSSL)
    if (preg_match('/Server Temp Key:\s*([^\r\n]+)/i', $output, $matches)) {
        $tempKey = trim($matches[1]);

        // Check if the temp key indicates PQC/hybrid exchange
        if (preg_match('/(MLKEM|Kyber|X25519MLKEM|X25519Kyber|ML-KEM)/i', $tempKey)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $tempKey;
            return $result;
        }
    }

    // Pattern 2: Check "Peer signing digest" or connection success with TLS 1.3
    // and verify the group was actually used
    if (preg_match('/New, TLSv1\.3/i', $output) || preg_match('/Protocol\s*:\s*TLSv1\.3/i', $output)) {
        // Check if the session indicates PQC key exchange
        if (preg_match('/(MLKEM|Kyber)/i', $output)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $group;
            return $result;
        }
    }

    // Pattern 3: Look for "Shared groups:" or similar indicators
    if (preg_match('/Shared groups:\s*([^\r\n]+)/i', $output, $matches)) {
        $sharedGroups = trim($matches[1]);
        if (preg_match('/(MLKEM|Kyber)/i', $sharedGroups)) {
            $result['supported'] = true;
            $result['negotiatedGroup'] = $group;
            return $result;
        }
    }

    // Check for connection errors
    if (preg_match('/connect:errno|Connection refused|Connection timed out|no peer certificate/i', $output)) {
        $result['error'] = 'Connection failed';
    } elseif (preg_match('/no protocols available|wrong version number/i', $output)) {
        // Server doesn't support TLS 1.3, PQC not applicable
        $result['error'] = 'TLS 1.3 not supported';
    } elseif (preg_match('/unknown group|unrecognized.*group/i', $output)) {
        // OpenSSL doesn't recognize this group
        $result['error'] = 'Group not supported by OpenSSL';
    }

    return $result;
}

/**
 * Creates a security check entry for PQC support.
 * 
 * @param array $pqcResult The result from detectPqcSupport()
 * @return array Security check entry compatible with sslyze-scan.php format
 */
function createPqcSecurityCheck($pqcResult)
{
    $check = [
        'name' => 'Post-Quantum Key Exchange (ML-KEM)',
        'passed' => $pqcResult['pqcSupported'],
        'severity' => 'INFO',
        'description' => ''
    ];

    if ($pqcResult['pqcSupported']) {
        $group = $pqcResult['negotiatedGroup'] ?? 'ML-KEM';
        $check['description'] = "Server supports post-quantum key exchange ({$group}).";
    } elseif ($pqcResult['error']) {
        $check['description'] = "PQC check inconclusive: {$pqcResult['error']}";
    } else {
        $check['description'] = 'Server does not support post-quantum (PQC) key exchange. Consider enabling for quantum-resistant TLS.';
    }

    return $check;
}

// If called directly (for testing), run standalone
if (basename($_SERVER['PHP_SELF']) === 'pqc-scan.php') {
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed. Use POST.']);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON in request body.']);
        exit;
    }

    $hostname = isset($input['hostname']) ? trim($input['hostname']) : '';
    $port = isset($input['port']) ? (int) $input['port'] : 443;

    if (empty($hostname)) {
        http_response_code(400);
        echo json_encode(['error' => 'Hostname is required.']);
        exit;
    }

    $result = detectPqcSupport($hostname, $port);
    $result['securityCheck'] = createPqcSecurityCheck($result);

    echo json_encode($result, JSON_PRETTY_PRINT);
}
