<?php
declare(strict_types=1);

/*
 * Checker helper functions
 */

function normalize_host(string $input): string
{
    $input = trim($input);

    if ($input === '') {
        return '';
    }

    if (!preg_match('#^https?://#i', $input)) {
        $input = 'https://' . $input;
    }

    $parts = parse_url($input);

    if (!isset($parts['host'])) {
        return '';
    }

    return rtrim(strtolower($parts['host']), '.');
}

function is_private_or_reserved_ip(string $ip): bool
{
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}

function is_valid_hostname(string $host): bool
{
    if ($host === '' || strlen($host) > 253) {
        return false;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return ALLOW_PRIVATE_IP_TARGETS || !is_private_or_reserved_ip($host);
    }

    return (bool) preg_match(
        '/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i',
        $host
    );
}

function resolve_public_ips(string $host): array
{
    $records = @dns_get_record($host, DNS_A + DNS_AAAA);
    $ips = [];

    if (!$records) {
        return [];
    }

    foreach ($records as $record) {
        $ip = $record['ip'] ?? $record['ipv6'] ?? null;

        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }

        if (!ALLOW_PRIVATE_IP_TARGETS && is_private_or_reserved_ip($ip)) {
            continue;
        }

        $ips[] = $ip;
    }

    return array_values(array_unique($ips));
}

function check_port(string $host, int $port, int $timeout = CONNECT_TIMEOUT): array
{
    $start = microtime(true);
    $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
    $responseMs = round((microtime(true) - $start) * 1000);

    if ($connection) {
        fclose($connection);

        return [
            'open' => true,
            'response_ms' => $responseMs,
            'error' => null,
        ];
    }

    return [
        'open' => false,
        'response_ms' => $responseMs,
        'error' => $errstr ?: 'Connection failed',
    ];
}

function normalize_headers(array $headers): array
{
    $result = [];

    foreach ($headers as $key => $value) {
        if (is_int($key)) {
            continue;
        }

        $result[$key] = is_array($value) ? implode(', ', $value) : (string) $value;
    }

    return $result;
}

function get_http_status(string $url): array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'HEAD',
            'timeout' => HTTP_TIMEOUT,
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 0,
            'user_agent' => USER_AGENT,
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ]);

    $headers = @get_headers($url, true, $context);

    if (!$headers || !isset($headers[0])) {
        return [
            'ok' => false,
            'status_line' => null,
            'status_code' => null,
            'location' => null,
            'headers' => [],
        ];
    }

    $statusLine = is_array($headers[0]) ? end($headers[0]) : $headers[0];
    preg_match('/\s(\d{3})\s/', (string) $statusLine, $match);

    return [
        'ok' => true,
        'status_line' => $statusLine,
        'status_code' => isset($match[1]) ? (int) $match[1] : null,
        'location' => $headers['Location'] ?? $headers['location'] ?? null,
        'headers' => normalize_headers($headers),
    ];
}

function get_ssl_info(string $host): array
{
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $host,
            'SNI_enabled' => true,
        ],
    ]);

    $client = @stream_socket_client(
        "ssl://{$host}:443",
        $errno,
        $errstr,
        TLS_TIMEOUT,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$client) {
        return [
            'valid_connection' => false,
            'error' => $errstr ?: 'TLS connection failed',
        ];
    }

    $meta = stream_get_meta_data($client);
    $params = stream_context_get_params($client);
    fclose($client);

    $certificate = $params['options']['ssl']['peer_certificate'] ?? null;

    if (!$certificate) {
        return [
            'valid_connection' => false,
            'error' => 'No certificate received',
        ];
    }

    $cert = openssl_x509_parse($certificate);

    if (!$cert) {
        return [
            'valid_connection' => false,
            'error' => 'Could not parse certificate',
        ];
    }

    $validTo = $cert['validTo_time_t'] ?? 0;
    $validFrom = $cert['validFrom_time_t'] ?? 0;
    $daysLeft = $validTo ? (int) floor(($validTo - time()) / 86400) : null;

    $health = 'unknown';

    if ($daysLeft !== null) {
        if ($daysLeft < 0) {
            $health = 'expired';
        } elseif ($daysLeft < SSL_WARNING_DAYS) {
            $health = 'warning';
        } else {
            $health = 'healthy';
        }
    }

    return [
        'valid_connection' => true,
        'health' => $health,
        'subject' => $cert['subject']['CN'] ?? null,
        'issuer' => $cert['issuer']['CN'] ?? null,
        'valid_from' => $validFrom ? date('Y-m-d H:i:s', $validFrom) : null,
        'valid_to' => $validTo ? date('Y-m-d H:i:s', $validTo) : null,
        'days_left' => $daysLeft,
        'expired' => $daysLeft !== null ? $daysLeft < 0 : null,
        'san' => $cert['extensions']['subjectAltName'] ?? null,
        'serial' => $cert['serialNumberHex'] ?? null,
        'signature_type' => $cert['signatureTypeSN'] ?? null,
        'tls_protocol' => $meta['crypto']['protocol'] ?? null,
        'tls_cipher' => $meta['crypto']['cipher_name'] ?? null,
        'tls_cipher_bits' => $meta['crypto']['cipher_bits'] ?? null,
    ];
}

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function badge(bool $ok): string
{
    return $ok
        ? '<span class="badge ok">OK</span>'
        : '<span class="badge bad">FAIL</span>';
}

function ssl_health_badge(?string $health): string
{
    return match ($health) {
        'healthy' => '<span class="badge ok">HEALTHY</span>',
        'warning' => '<span class="badge warn">EXPIRING SOON</span>',
        'expired' => '<span class="badge bad">EXPIRED</span>',
        default => '<span class="badge warn">UNKNOWN</span>',
    };
}
