<?php
declare(strict_types=1);

/*
 * Checker v1.1.0
 * Simple HTTP / HTTPS / SSL / TLS website checker
 *
 * Changelog:
 * v1.1.0
 * - Added app versioning
 * - Added redirect Location detection
 * - Added SSL health status badge
 * - Added TLS protocol/cipher detection
 * - Added HTTP/HTTPS response headers
 * - Added collapsible Raw JSON
 * - Added Copy JSON button
 * - Added Open JSON API button
 *
 * v1.0.0
 * - Initial release
 */

const APP_NAME = 'checker';
const APP_VERSION = '1.1.0';

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
        return !is_private_or_reserved_ip($host);
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

        if ($ip && filter_var($ip, FILTER_VALIDATE_IP) && !is_private_or_reserved_ip($ip)) {
            $ips[] = $ip;
        }
    }

    return array_values(array_unique($ips));
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
            'timeout' => 8,
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 0,
            'user_agent' => 'checker/' . APP_VERSION,
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
        } elseif ($daysLeft < 14) {
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

$input = $_GET['host'] ?? '';
$format = $_GET['format'] ?? 'html';
$host = normalize_host((string) $input);

$result = [
    'app' => APP_NAME,
    'version' => APP_VERSION,
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

$jsonOutput = json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo $jsonOutput;
    exit;
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Checker v<?= e(APP_VERSION) ?> - HTTP HTTPS SSL TLS</title>
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

h2 {
    margin-top: 0;
}

.subtitle {
    margin: 0;
    color: var(--muted);
}

.version {
    display: inline-block;
    margin-top: 10px;
    padding: 5px 10px;
    border: 1px solid #2d4f84;
    background: rgba(56, 189, 248, 0.08);
    border-radius: 999px;
    color: var(--muted);
    font-size: 0.85rem;
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

.button.secondary,
button.secondary {
    background: #1f2937;
    color: var(--text);
    border: 1px solid #2d4f84;
}

.actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 12px;
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

details {
    margin-top: 12px;
}

summary {
    cursor: pointer;
    color: var(--accent);
    font-weight: 700;
    margin-bottom: 10px;
}

.footer {
    color: var(--muted);
    font-size: 0.85rem;
    text-align: center;
    margin-top: 24px;
}

.copy-status {
    color: var(--ok);
    font-size: 0.9rem;
    margin-top: 8px;
    display: none;
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

    .actions {
        display: grid;
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>Checker</h1>
        <p class="subtitle">HTTP / HTTPS / SSL / TLS website checker</p>
        <span class="version">v<?= e(APP_VERSION) ?></span>
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
            <div class="actions">
                <a class="button secondary" href="?host=<?= urlencode($host) ?>&format=json" target="_blank">
                    Open JSON API
                </a>
                <button class="secondary" type="button" onclick="copyJson()">Copy JSON</button>
            </div>
            <div id="copyStatus" class="copy-status">JSON copied.</div>
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
                    <?php if (!empty($result['http_status']['location'])): ?>
                        <div class="small">
                            Redirect Location:<br>
                            <code><?= e($result['http_status']['location']) ?></code>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="item">
                    <div class="label">HTTPS Status</div>
                    <div class="value">
                        <?= e($result['https_status']['status_line'] ?? 'No response') ?>
                    </div>
                    <?php if (!empty($result['https_status']['location'])): ?>
                        <div class="small">
                            Redirect Location:<br>
                            <code><?= e($result['https_status']['location']) ?></code>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <details>
                <summary>Show HTTP Headers</summary>
                <pre><?= e(json_encode($result['http_status']['headers'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
            </details>

            <details>
                <summary>Show HTTPS Headers</summary>
                <pre><?= e(json_encode($result['https_status']['headers'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
            </details>
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
                        <div class="label">Health</div>
                        <div class="value"><?= ssl_health_badge($result['ssl']['health'] ?? null) ?></div>
                    </div>
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
                        <div class="label">TLS Protocol</div>
                        <div class="value"><?= e($result['ssl']['tls_protocol'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">TLS Cipher</div>
                        <div class="value"><?= e($result['ssl']['tls_cipher'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Cipher Bits</div>
                        <div class="value"><?= e($result['ssl']['tls_cipher_bits'] ?? '-') ?></div>
                    </div>
                    <div class="item">
                        <div class="label">Signature</div>
                        <div class="value"><?= e($result['ssl']['signature_type'] ?? '-') ?></div>
                    </div>
                </div>

                <details>
                    <summary>Show Subject Alternative Names</summary>
                    <pre><?= e($result['ssl']['san'] ?? '-') ?></pre>
                </details>

                <details>
                    <summary>Show Certificate Serial</summary>
                    <pre><?= e($result['ssl']['serial'] ?? '-') ?></pre>
                </details>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>Raw JSON</h2>
            <details>
                <summary>Show Raw JSON</summary>
                <pre id="jsonOutput"><?= e($jsonOutput) ?></pre>
            </details>
        </div>

    <?php endif; ?>

    <div class="footer">
        checker v<?= e(APP_VERSION) ?> · no shell execution · public hosts only
    </div>

</div>

<script>
const jsonData = <?= json_encode($jsonOutput, JSON_UNESCAPED_SLASHES) ?>;

function copyJson() {
    navigator.clipboard.writeText(jsonData).then(() => {
        const el = document.getElementById('copyStatus');
        if (el) {
            el.style.display = 'block';
            setTimeout(() => {
                el.style.display = 'none';
            }, 1800);
        }
    });
}
</script>
</body>
</html>
