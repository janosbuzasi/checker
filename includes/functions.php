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

    $unbracketedInput = trim($input, '[]');

    if (filter_var($unbracketedInput, FILTER_VALIDATE_IP)) {
        return strtolower($unbracketedInput);
    }

    if (!preg_match('#^https?://#i', $input)) {
        $input = 'https://' . $input;
    }

    $parts = parse_url($input);

    if (!isset($parts['host'])) {
        return '';
    }

    return rtrim(strtolower(trim($parts['host'], '[]')), '.');
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
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!ALLOW_PRIVATE_IP_TARGETS && is_private_or_reserved_ip($host)) {
            return [];
        }

        return [$host];
    }

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

function format_url_host(string $host): string
{
    return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ? "[{$host}]"
        : $host;
}

function check_port(string $host, int $port, int $timeout = CONNECT_TIMEOUT): array
{
    $start = microtime(true);
    $socketHost = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ? "tcp://[{$host}]"
        : $host;
    $connection = @fsockopen($socketHost, $port, $errno, $errstr, $timeout);
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

function get_reverse_dns(string $ip): ?string
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $hostname = @gethostbyaddr($ip);

    if (!$hostname || $hostname === $ip) {
        return null;
    }

    return rtrim(strtolower($hostname), '.');
}

function find_rdap_entity(array $entities, array $wantedRoles): ?array
{
    foreach ($entities as $entity) {
        $roles = $entity['roles'] ?? [];

        if (array_intersect($wantedRoles, $roles)) {
            return $entity;
        }

        $nested = find_rdap_entity($entity['entities'] ?? [], $wantedRoles);

        if ($nested) {
            return $nested;
        }
    }

    return null;
}

function rdap_vcard_value(?array $entity, string $property): ?string
{
    $properties = $entity['vcardArray'][1] ?? [];

    foreach ($properties as $entry) {
        if (($entry[0] ?? null) !== $property) {
            continue;
        }

        $value = $entry[3] ?? null;

        if (is_array($value)) {
            $value = implode(', ', array_filter($value, 'is_string'));
        }

        return is_scalar($value) ? (string) $value : null;
    }

    return null;
}

function get_ip_asn(string $ip): array
{
    $query = null;

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $query = implode('.', array_reverse(explode('.', $ip))) . '.origin.asn.cymru.com';
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $packed = inet_pton($ip);

        if ($packed !== false) {
            $hex = bin2hex($packed);
            $query = implode('.', array_reverse(str_split($hex))) . '.origin6.asn.cymru.com';
        }
    }

    if ($query === null) {
        return [];
    }

    $records = @dns_get_record($query, DNS_TXT);
    $text = $records[0]['txt'] ?? null;

    if (!$text) {
        return [];
    }

    $parts = array_map('trim', explode('|', $text));

    return [
        'asn' => isset($parts[0]) ? 'AS' . ltrim($parts[0], 'ASas') : null,
        'announced_prefix' => $parts[1] ?? null,
        'asn_country' => $parts[2] ?? null,
        'registry' => $parts[3] ?? null,
        'allocated_at' => $parts[4] ?? null,
    ];
}

function fetch_json_url(string $url, int $timeout): ?array
{
    $body = false;

    if (filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOL)) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'ignore_errors' => true,
                'follow_location' => 1,
                'max_redirects' => 5,
                'user_agent' => USER_AGENT,
                'header' => "Accept: application/rdap+json, application/json\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
    }

    if ($body === false && function_exists('curl_init')) {
        $curl = curl_init($url);

        if ($curl !== false) {
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => $timeout,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_USERAGENT => USER_AGENT,
                CURLOPT_HTTPHEADER => ['Accept: application/rdap+json, application/json'],
            ]);
            $body = curl_exec($curl);
            curl_close($curl);
        }
    }

    if (!is_string($body)) {
        return null;
    }

    $data = json_decode($body, true);

    return is_array($data) ? $data : null;
}

function get_ip_registration(string $ip): array
{
    if (!filter_var($ip, FILTER_VALIDATE_IP) || is_private_or_reserved_ip($ip)) {
        return [
            'available' => false,
            'error' => 'RDAP is only available for public IP addresses',
        ];
    }

    $data = fetch_json_url(RDAP_BASE_URL . rawurlencode($ip), RDAP_TIMEOUT);

    if ($data === null) {
        return [
            'available' => false,
            'error' => 'RDAP request failed',
        ];
    }

    if (isset($data['errorCode'])) {
        return [
            'available' => false,
            'error' => $data['title'] ?? 'Invalid RDAP response',
        ];
    }

    $registrant = find_rdap_entity($data['entities'] ?? [], ['registrant']);
    $abuse = find_rdap_entity($data['entities'] ?? [], ['abuse']);
    $cidr = [];

    foreach ($data['cidr0_cidrs'] ?? [] as $block) {
        $prefix = $block['v4prefix'] ?? $block['v6prefix'] ?? null;

        if ($prefix !== null && isset($block['length'])) {
            $cidr[] = $prefix . '/' . $block['length'];
        }
    }

    return array_merge([
        'available' => true,
        'name' => $data['name'] ?? null,
        'handle' => $data['handle'] ?? null,
        'type' => $data['type'] ?? null,
        'country' => $data['country'] ?? null,
        'start_address' => $data['startAddress'] ?? null,
        'end_address' => $data['endAddress'] ?? null,
        'cidr' => $cidr,
        'parent_handle' => $data['parentHandle'] ?? null,
        'port43' => $data['port43'] ?? null,
        'registrant' => rdap_vcard_value($registrant, 'fn'),
        'abuse_name' => rdap_vcard_value($abuse, 'fn'),
        'abuse_email' => rdap_vcard_value($abuse, 'email'),
    ], get_ip_asn($ip));
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
    $socketHost = format_url_host($host);
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
        "ssl://{$socketHost}:443",
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
