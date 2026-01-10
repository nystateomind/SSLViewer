<?php
/**
 * Enterprise-Specific Detection Configuration
 * 
 * This file contains custom detection logic for your organization's infrastructure.
 * It is separate from the main codebase to allow updates without losing customizations.
 * 
 * Modify the functions below to match your environment.
 */

/**
 * Detects infrastructure based on enterprise-specific criteria.
 * This runs BEFORE generic detection, so enterprise rules take priority.
 * 
 * @param string $hostname The target hostname
 * @param string $ipAddress The resolved IP address of the target
 * @param string $headers The raw HTTP response headers
 * @return string|null The detected infrastructure name, or null if not detected
 */
function enterprise_detect_infrastructure($hostname, $ipAddress, $headers)
{

    // --- VMware Avi Detection by IP Range ---
    // Add your Avi VIP (Virtual IP) ranges here
    $aviIpRanges = [
        // Example formats:
        // '10.100.0.0/16',      // CIDR notation
        // '192.168.50.',        // Prefix match
        // '172.16.100.10',      // Exact IP
    ];

    foreach ($aviIpRanges as $range) {
        if (ip_in_range($ipAddress, $range)) {
            return 'VMware Avi';
        }
    }

    // --- F5 BIG-IP Detection by IP Range ---
    $f5IpRanges = [
        // Add your F5 VIP ranges here
    ];

    foreach ($f5IpRanges as $range) {
        if (ip_in_range($ipAddress, $range)) {
            return 'F5 BIG-IP';
        }
    }

    // --- Citrix NetScaler Detection by IP Range ---
    $netscalerIpRanges = [
        // Add your NetScaler VIP ranges here
    ];

    foreach ($netscalerIpRanges as $range) {
        if (ip_in_range($ipAddress, $range)) {
            return 'Citrix NetScaler';
        }
    }

    // --- Custom Header Detection ---
    // Add any custom headers your infrastructure uses
    // Example: if (preg_match('/^X-My-Custom-Header:/mi', $headers)) {
    //     return 'My Custom LB';
    // }

    // --- Hostname Pattern Detection ---
    // Example: if (preg_match('/\.avi\.mycompany\.com$/i', $hostname)) {
    //     return 'VMware Avi';
    // }

    return null; // No enterprise-specific detection matched
}

/**
 * Helper function to check if an IP is within a range.
 * Supports CIDR notation, prefix matching, and exact IP matching.
 * 
 * @param string $ip The IP address to check
 * @param string $range The range to check against (CIDR, prefix, or exact)
 * @return bool True if IP is in range
 */
function ip_in_range($ip, $range)
{
    // Exact match
    if ($ip === $range) {
        return true;
    }

    // Prefix match (e.g., '10.100.50.')
    if (substr($range, -1) === '.' && strpos($ip, $range) === 0) {
        return true;
    }

    // CIDR notation (e.g., '10.100.0.0/16')
    if (strpos($range, '/') !== false) {
        list($subnet, $bits) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - (int) $bits);
        $subnet_long &= $mask;
        return ($ip_long & $mask) === $subnet_long;
    }

    return false;
}
