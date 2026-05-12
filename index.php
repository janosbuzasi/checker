<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/functions.php';

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
<title><?= e(APP_TITLE) ?> v<?= e(APP_VERSION) ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div class="container">

    <div class="header">
        <h1><?= e(APP_TITLE) ?></h1>
        <p class="subtitle"><?= e(APP_SUBTITLE) ?></p>
        <span class="version">v<?= e(APP_VERSION) ?></span>
    </div>

    <div class="card">
        <form method="get">
            <div class="form-row">
                <input
                    type="text"
                    name="host"
                    placeholder="<?= e(DEFAULT_PLACEHOLDER) ?>"
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

                <?php if (ENABLE_COPY_JSON): ?>
                    <button class="secondary" type="button" onclick="copyJson()">Copy JSON</button>
                <?php endif; ?>
            </div>

            <?php if (ENABLE_COPY_JSON): ?>
                <div id="copyStatus" class="copy-status">JSON copied.</div>
            <?php endif; ?>
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

            <?php if (ENABLE_HTTP_HEADERS): ?>
                <details>
                    <summary>Show HTTP Headers</summary>
                    <pre><?= e(json_encode($result['http_status']['headers'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
                </details>

                <details>
                    <summary>Show HTTPS Headers</summary>
                    <pre><?= e(json_encode($result['https_status']['headers'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
                </details>
            <?php endif; ?>
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
                            <?php elseif (($result['ssl']['days_left'] ?? 999) < SSL_WARNING_DAYS): ?>
                                <span class="warn"><?= e($result['ssl']['days_left']) ?> days</span>
                            <?php else: ?>
                                <span class="ok"><?= e($result['ssl']['days_left']) ?> days</span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <?php if (ENABLE_TLS_DETAILS): ?>
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
                    <?php endif; ?>
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

        <?php if (ENABLE_RAW_JSON): ?>
            <div class="card">
                <h2>Raw JSON</h2>
                <details>
                    <summary>Show Raw JSON</summary>
                    <pre id="jsonOutput"><?= e($jsonOutput) ?></pre>
                </details>
            </div>
        <?php endif; ?>

    <?php endif; ?>

    <div class="footer">
        <?= e(FOOTER_TEXT) ?>
    </div>

</div>

<script src="assets/js/script.js"></script>
</body>
</html>
