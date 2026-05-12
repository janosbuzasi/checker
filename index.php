<?php
declare(strict_types=1);

/*
 * Checker
 * Simple HTTP / HTTPS / SSL / TLS website checker
 *
 * Web UI:
 *   /checker/index.php
 *
 * Check:
 *   /checker/index.php?host=example.com
 *
 * JSON API:
 *   /checker/index.php?host=example.com&format=json
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

    $host = strtolower($parts['host']);
    $host = rtrim($host, '.');

    return $host;
}

function is_private_or_reserved_ip(string $ip): bool
{
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
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

        if (
            $ip &&
            filter_var($ip, FILTER_VALIDATE_IP) &&
            !is_private_or_reserved_ip($ip)
        ) {
            $ips[] = $ip;
        }
    }

    return array_values(array_unique($ips));
}

function is_valid_hostname(string $host): bool
{
    if ($host === '' || strlen($host) > 253) {
        return false;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return !is_private_or_reserved_ip($host);
    }

    return (bool) preg_match(
        '/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i',
        $host
    );
}

function check_port(string $host, int $port, int $timeout = 5): array
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

function get_http_status(string $url): array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'HEAD',
            'timeout' => 8,
            'ignore_errors' => true,
            'user_agent' => 'checker/1.0',
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
        ];
    }

    $statusLine = is_array($headers[0]) ? end($headers[0]) : $headers[0];

    preg_match('/\s(\d{3})\s/', (string) $statusLine, $match);

    return [
        'ok' => true,
        'status_line' => $statusLine,
        'status_code' => isset($match[1]) ? (int) $match[1] : null,
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
        10,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$client) {
        return [
            'valid_connection' => false,
            'error' => $errstr ?: 'TLS connection failed',
        ];
    }

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

    return [
        'valid_connection' => true,
        'subject' => $cert['subject']['CN'] ?? null,
        'issuer' => $cert['issuer']['CN'] ?? null,
        'valid_from' => $validFrom ? date('Y-m-d H:i:s', $validFrom) : null,
        'valid_to' => $validTo ? date('Y-m-d H:i:s', $validTo) : null,
        'days_left' => $daysLeft,
        'expired' => $daysLeft !== null ? $daysLeft < 0 : null,
        'san' => $cert['extensions']['subjectAltName'] ?? null,
        'serial' => $cert['serialNumberHex'] ?? null,
        'signature_type' => $cert['signatureTypeSN'] ?? null,
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

$input = $_GET['host'] ?? '';
$format = $_GET['format'] ?? 'html';
$host = normalize_host((string) $input);

$result = [
    'app' => 'checker',
    'input' => $input,
    'host' => $host,
    'checked_at' => date('c'),
    'error' => null,
];

if ($host !== '') {
    if (!is_valid_hostname($host)) {
        $result['error'] = 'Invalid or blocked hostname';
    } else {
        $ips = resolve_public_ips($host);

        if (!$ips) {
            $result['error'] = 'Host does not resolve to a public IP';
        } else {
            $result['ips'] = $ips;
            $result['http'] = check_port($host, 80);
            $result['https'] = check_port($host, 443);
            $result['http_status'] = get_http_status("http://{$host}/");
            $result['https_status'] = get_http_status("https://{$host}/");
            $result['ssl'] = $result['https']['open'] ? get_ssl_info($host) : null;
        }
    }
}

if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Checker - HTTP HTTPS SSL TLS</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
    --bg: #0f172a;
    --card: #111827;
    --card2: #1f2937;
    --border: #374151;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --accentText: #082f49;
    --ok: #22c55e;
    --bad: #ef4444;
    --warn: #facc15;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 32px 16px;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background:
        radial-gradient(circle at top, #1e293b 0, var(--bg) 42%),
        var(--bg);
    color: var(--text);
}

.container {
    max-width: 920px;
    margin: 0 auto;
}

.header {
    margin-bottom: 22px;
}

h1 {
    margin: 0 0 8px;
    font-size: 2.1rem;
}

.subtitle {
    margin: 0;
    color: var(--muted);
}

.card {
    background: rgba(17, 24, 39, 0.92);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.22);
}

.form-row {
    display: flex;
    gap: 10px;
}

input[type="text"] {
    flex: 1;
    padding: 14px 15px;
    border-radius: 12px;
    border: 1px solid #4b5563;
    background: #020617;
    color: #fff;
    font-size: 1rem;
    outline: none;
}

input[type="text"]:focus {
    border-color: var(--accent);
}

button,
.button {
    padding: 14px 18px;
    border: 0;
    border-radius: 12px;
    background: var(--accent);
    color: var(--accentText);
    font-weight: 800;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}

.grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.item {
    background: rgba(31, 41, 55, 0.75);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px;
}

.label {
    color: var(--muted);
    font-size: 0.9rem;
    margin-bottom: 5px;
}

.value {
    font-weight: 700;
    word-break: break-word;
}

.badge {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 0.8rem;
    font-weight: 900;
}

.ok {
    color: var(--ok);
}

.bad {
    color: var(--bad);
}

.warn {
    color: var(--warn);
}

pre {
    margin: 0;
    padding: 14px;
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
}

code {
    color: var(--accent);
}

a {
    color: var(--accent);
}

.small {
    color: var(--muted);
    font-size: 0.92rem;
}

.footer {
    color: var(--muted);
    font-size: 0.85rem;
    text-align: center;
    margin-top: 24px;
}

@media (max-width: 720px) {
    .form-row,
    .grid {
        grid-template-columns: 1fr;
        display: grid;
    }

    button,
    .button {
        width: 100%;
        text-align: center;
    }
}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>Checker</h1>
        <p class="subtitle">HTTP / HTTPS / SSL / TLS website checker</p>
    </div>

    <div class="card">
        <form method="get">
            <div class="form-row">
                <input
                    type="text"
                    name="host"
                    placeholder="webtrash.ch"
                    value="<?= e($input) ?>"
                    autocomplete="off"
                >
                <button type="submit">Check</button>
            </div>
        </form>

        <p class="small">
            Examples:
            <code>webtrash.ch</code>,
            <code>https://github.com</code>,
            <code>https://example.com/login</code>
        </p>

        <?php if ($host): ?>
            <p class="small">
                JSON API:
                <a href="?host=<?= urlencode($host) ?>&format=json">
                    ?host=<?= e($host) ?>&amp;format=json
                </a>
            </p>
        <?php endif; ?>
    </div>

    <?php if ($result['error']): ?>
        <div class="card">
            <h2>Error</h2>
            <p class="bad"><?= e($result['error']) ?></p>
        </div>
    <?php elseif ($host): ?>

        <div class="card">
            <h2>Target</h2>
            <div class="grid">
                <div class="item">
                    <div class="label">Host</div>
                    <div class="value"><?= e($host) ?></div>
                </div>
                <div class="item">
                    <div class="label">Resolved IPs</div>
                    <div class="value"><?= e(implode(', ', $result['ips'] ?? [])) ?></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Connectivity</h2>
            <div class="grid">
                <div class="item">
                    <div class="label">HTTP Port 80</div>
                    <div class="value">
                        <?= badge((bool) $result['http']['open']) ?>
                        <?= e($result['http']['response_ms']) ?> ms
                    </div>
                </div>
                <div class="item">
                    <div class="label">HTTPS Port 443</div>
                    <div class="value">
                        <?= badge((bool) $result['https']['open']) ?>
                        <?= e($result['https']['response_ms']) ?> ms
                    </div>
                </div>
                <div class="item">
                    <div class="label">HTTP Status</div>
                    <div class="value">
                        <?= e($result['http_status']['status_line'] ?? 'No response') ?>
                    </div>
                </div>
                <div class="item">
                    <div class="label">HTTPS Status</div>
                    <div class="value">
                        <?= e($result['https_status']['status_line'] ?? 'No response') ?>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>SSL / TLS Certificate</h2>

            <?php if (!$result['ssl']): ?>
                <p class="bad">No HTTPS connection.</p>
            <?php elseif (!$result['ssl']['valid_connection']): ?>
                <p class="bad"><?= e($result['ssl']['error']) ?></p>
            <?php else: ?>
                <div class="grid">
                    <div class="item">
                        <div class="label">Subject</div>
                        <div class="value"><?= e($result['ssl']['subject'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Issuer</div>
                        <div class="value"><?= e($result['ssl']['issuer'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Valid From</div>
                        <div class="value"><?= e($result['ssl']['valid_from'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Valid To</div>
                        <div class="value"><?= e($result['ssl']['valid_to'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Days Left</div>
                        <div class="value">
                            <?php if (($result['ssl']['expired'] ?? false) === true): ?>
                                <span class="bad"><?= e($result['ssl']['days_left']) ?> expired</span>
                            <?php elseif (($result['ssl']['days_left'] ?? 999) < 14): ?>
                                <span class="warn"><?= e($result['ssl']['days_left']) ?> days</span>
                            <?php else: ?>
                                <span class="ok"><?= e($result['ssl']['days_left']) ?> days</span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="item">
                        <div class="label">Signature</div>
                        <div class="value"><?= e($result['ssl']['signature_type'] ?? '-') ?></div>
                    </div>
                </div>

                <p class="small">Subject Alternative Names</p>
                <pre><?= e($result['ssl']['san'] ?? '-') ?></pre>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>Raw JSON</h2>
            <pre><?= e(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
        </div>

    <?php endif; ?>

    <div class="footer">
        checker · no shell execution · public hosts only
    </div>

</div>
</body>
</html>
