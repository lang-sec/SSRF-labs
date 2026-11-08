<?php

declare(strict_types=1);

const LAB_APP_PORT = 8080;
const LAB_INTERNAL_PORT = 8081;
const LAB_METADATA_PORT = 8082;
const LAB_REDIRECT_PORT = 8083;
const LAB_CALLBACK_PORT = 8084;
const LAB_GOPHER_PORT = 6380;
const LAB_REBIND_DOMAIN = 'cdn-preview.ssrf.lab';
const LAB_REBIND_PREVIEW_HOST = 'avatar-7f3a.cdn-preview.ssrf.lab';
const LAB_REBIND_VALIDATION_IP = '203.0.113.77';
const LAB_REBIND_CONNECTION_IP = '127.0.0.1';
const LAB_DUAL_DNS_DOMAIN = 'dual-cdn.ssrf.lab';
const LAB_DUAL_DNS_PUBLIC_IP = '203.0.113.88';
const LAB_TARGET_HOST = '10.220.2.6';
const LAB_TARGET_PORT = 8080;

function lab_root(): string
{
    return dirname(__DIR__);
}

function lab_storage_dir(): string
{
    $dir = lab_root() . DIRECTORY_SEPARATOR . 'storage';
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }

    return $dir;
}

function lab_runtime_dir(): string
{
    $dir = lab_root() . DIRECTORY_SEPARATOR . '.runtime';
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }

    return $dir;
}

function lab_json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function lab_text_response(string $body, int $status = 200, string $contentType = 'text/plain; charset=utf-8'): never
{
    http_response_code($status);
    header('Content-Type: ' . $contentType);
    header('Cache-Control: no-store');
    echo $body;
    exit;
}

function lab_read_json_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function lab_host_without_brackets(string $host): string
{
    return strtolower(trim($host, "[] \t\n\r\0\x0B"));
}

function lab_ipv4_from_long(int $value): ?string
{
    if ($value < 0 || $value > 4294967295) {
        return null;
    }

    return long2ip($value);
}

function lab_is_rebind_host(string $host): bool
{
    $host = lab_host_without_brackets($host);

    return $host === LAB_REBIND_DOMAIN
        || str_ends_with($host, '.' . LAB_REBIND_DOMAIN);
}

function lab_is_dual_dns_host(string $host): bool
{
    $host = lab_host_without_brackets($host);

    return $host === LAB_DUAL_DNS_DOMAIN
        || str_ends_with($host, '.' . LAB_DUAL_DNS_DOMAIN);
}

function lab_is_cloud_metadata_host(string $host): bool
{
    return in_array(lab_host_without_brackets($host), [
        'metadata.google.internal',
        'instance-data.ec2.internal',
        'metadata.azure.internal',
    ], true);
}

function lab_parse_ipv4_literal(string $host): ?string
{
    if ($host === '' || !str_contains($host, '.')) {
        return null;
    }

    $parts = explode('.', $host);
    if (count($parts) < 2 || count($parts) > 4) {
        return null;
    }

    $numbers = [];
    foreach ($parts as $part) {
        if ($part === '') {
            return null;
        }

        if (preg_match('/^0x([0-9a-f]+)$/i', $part, $match) === 1) {
            $numbers[] = (int) hexdec($match[1]);
            continue;
        }

        if (preg_match('/^0[0-7]+$/', $part) === 1) {
            $numbers[] = (int) octdec($part);
            continue;
        }

        if (ctype_digit($part)) {
            $numbers[] = (int) $part;
            continue;
        }

        return null;
    }

    $value = 0;
    $lastIndex = count($numbers) - 1;
    foreach ($numbers as $index => $number) {
        if ($index === $lastIndex) {
            $bits = 8 * (4 - $lastIndex);
            if ($number < 0 || $number >= (2 ** $bits)) {
                return null;
            }
            $value += $number;
            break;
        }

        if ($number < 0 || $number > 255) {
            return null;
        }
        $value += $number << (8 * (3 - $index));
    }

    return lab_ipv4_from_long($value);
}

function lab_normalize_host(string $host): ?string
{
    $host = lab_host_without_brackets($host);

    if ($host === '') {
        return null;
    }

    $trimmedHost = rtrim($host, '.');
    if ($trimmedHost === 'localhost') {
        return '127.0.0.1';
    }

    if (lab_is_rebind_host($host)) {
        return $host;
    }

    if (lab_is_dual_dns_host($host)) {
        return $host;
    }

    if (lab_is_cloud_metadata_host($host)) {
        return $host;
    }

    $packed = @inet_pton($host);
    if ($packed !== false && strlen($packed) === 16) {
        $mappedPrefix = str_repeat("\0", 10) . "\xff\xff";
        if (substr($packed, 0, 12) === $mappedPrefix) {
            $unpacked = unpack('Nvalue', substr($packed, 12, 4));
            return lab_ipv4_from_long((int) ($unpacked['value'] ?? 0));
        }
    }

    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return $host;
    }

    if (preg_match('/^\d+$/', $host) === 1) {
        return lab_ipv4_from_long((int) $host);
    }

    if (preg_match('/^0x([0-9a-f]+)$/i', $host, $matches) === 1) {
        $value = hexdec($matches[1]);
        return is_float($value) ? null : lab_ipv4_from_long((int) $value);
    }

    return lab_parse_ipv4_literal($host);
}

function lab_is_loopback_ip(string $ip): bool
{
    $normalized = lab_host_without_brackets($ip);

    if ($normalized === '::1') {
        return true;
    }

    if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return false;
    }

    return str_starts_with($normalized, '127.');
}

function lab_is_private_ip(string $ip): bool
{
    if (lab_is_loopback_ip($ip)) {
        return true;
    }

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return $ip === '::1'
            || str_starts_with(strtolower($ip), 'fc')
            || str_starts_with(strtolower($ip), 'fd')
            || str_starts_with(strtolower($ip), 'fe80:');
    }

    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

function lab_parse_http_url(string $url): ?array
{
    $parts = parse_url($url);
    if (!is_array($parts)) {
        return null;
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = (string) ($parts['host'] ?? '');
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        return null;
    }

    $port = isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'https' ? 443 : 80);

    return [
        'parts' => $parts,
        'scheme' => $scheme,
        'host' => lab_host_without_brackets($host),
        'port' => $port,
    ];
}

function lab_url_with_host(string $url, string $newHost): string
{
    $parts = parse_url($url);
    if (!is_array($parts)) {
        return $url;
    }

    $scheme = $parts['scheme'] ?? 'http';
    $auth = '';
    if (isset($parts['user'])) {
        $auth = $parts['user'];
        if (isset($parts['pass'])) {
            $auth .= ':' . $parts['pass'];
        }
        $auth .= '@';
    }

    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    $path = $parts['path'] ?? '/';
    $query = isset($parts['query']) ? '?' . $parts['query'] : '';
    $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';

    return $scheme . '://' . $auth . $newHost . $port . $path . $query . $fragment;
}

function lab_expected_secret_path(): string
{
    return realpath(lab_root() . DIRECTORY_SEPARATOR . 'secrets' . DIRECTORY_SEPARATOR . 'level6.txt') ?: '';
}

function lab_file_url_to_path(string $url): ?string
{
    $parts = parse_url($url);
    if (!is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'file') {
        return null;
    }

    $path = urldecode((string) ($parts['path'] ?? ''));
    if (preg_match('/^\/[A-Za-z]:\//', $path) === 1) {
        $path = substr($path, 1);
    }

    return realpath($path) ?: null;
}

function lab_boundary_check(int $level, string $url): array
{
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

    if ($scheme === 'file') {
        if ($level !== 6) {
            return ['ok' => false, 'reason' => '实验边界：只有第 6 关允许读取指定的教学文件。'];
        }

        $path = lab_file_url_to_path($url);
        $expected = lab_expected_secret_path();
        if ($path === null || $expected === '' || $path !== $expected) {
            return ['ok' => false, 'reason' => '实验边界：file:// 仅允许读取 secrets/level6.txt。'];
        }

        return [
            'ok' => true,
            'kind' => 'file',
            'path' => $path,
            'host' => '',
            'port' => 0,
        ];
    }

    if ($scheme === 'gopher') {
        if ($level !== 13) {
            return ['ok' => false, 'reason' => '实验边界：gopher 只用于第 13 关。'];
        }

        $parts = parse_url($url);
        $host = lab_host_without_brackets((string) ($parts['host'] ?? ''));
        $port = (int) ($parts['port'] ?? 0);
        if ($host !== '127.0.0.1' || $port !== LAB_GOPHER_PORT) {
            return ['ok' => false, 'reason' => '实验边界：gopher 只允许访问 127.0.0.1:6380 的模拟服务。'];
        }

        return [
            'ok' => true,
            'kind' => 'gopher',
            'host' => $host,
            'port' => $port,
        ];
    }

    $parsed = lab_parse_http_url($url);
    if ($parsed === null) {
        return ['ok' => false, 'reason' => '实验边界：只允许 http 或 https URL。'];
    }

    $allowedPorts = [LAB_APP_PORT, LAB_INTERNAL_PORT, LAB_METADATA_PORT, LAB_REDIRECT_PORT, LAB_CALLBACK_PORT];
    if (!in_array($parsed['port'], $allowedPorts, true)) {
        return ['ok' => false, 'reason' => '实验边界：目标端口必须是 8080 到 8084。'];
    }

    // 第 1/12 关的验证端点：10.220.2.6:8080 是非本地的外部验证服务。
    // 只有这两个关卡可以访问该地址，其余关卡仍然只能访问回环教学服务。
    if (in_array($level, [1, 12], true)
        && $parsed['host'] === LAB_TARGET_HOST
        && $parsed['port'] === LAB_TARGET_PORT) {
        return [
            'ok' => true,
            'kind' => 'http',
            'host' => $parsed['host'],
            'normalizedHost' => $parsed['host'],
            'port' => $parsed['port'],
            'scheme' => $parsed['scheme'],
        ];
    }

    $normalizedHost = lab_normalize_host($parsed['host']);
    if ($normalizedHost === null) {
        return ['ok' => false, 'reason' => '实验边界：仅允许本机回环地址、localhost 和教学重绑定域名。'];
    }

    $isRebindHost = lab_is_rebind_host($normalizedHost);
    $isDualDnsHost = lab_is_dual_dns_host($normalizedHost);
    $isCloudMetadataHost = lab_is_cloud_metadata_host($normalizedHost);
    $isSpecialHost = $isRebindHost || $isDualDnsHost || $isCloudMetadataHost;

    if (!$isSpecialHost && !lab_is_loopback_ip($normalizedHost)) {
        return ['ok' => false, 'reason' => '实验边界：目标地址必须位于本机回环网段。'];
    }

    if ($isRebindHost && $level !== 5) {
        return ['ok' => false, 'reason' => '实验边界：CDN 重绑定域名只用于第 5 关。'];
    }

    if ($isDualDnsHost && $level !== 9) {
        return ['ok' => false, 'reason' => '实验边界：混合 DNS 域名只用于第 9 关。'];
    }

    if ($isCloudMetadataHost && $level !== 14) {
        return ['ok' => false, 'reason' => '实验边界：云元数据内部域名只用于第 14 关。'];
    }

    return [
        'ok' => true,
        'kind' => 'http',
        'host' => $parsed['host'],
        'normalizedHost' => $normalizedHost,
        'port' => $parsed['port'],
        'scheme' => $parsed['scheme'],
    ];
}

function lab_result_error(string $message, int $started, string $decision = 'error'): array
{
    return [
        'ok' => false,
        'blocked' => $decision === 'blocked',
        'validation' => [
            'decision' => $decision,
            'message' => $message,
        ],
        'transport' => [
            'method' => 'GET',
            'target' => '',
            'finalUrl' => '',
            'resolvedIp' => null,
        ],
        'response' => [
            'status' => 0,
            'durationMs' => (int) round((hrtime(true) - $started) / 1_000_000),
            'bytes' => 0,
            'body' => $message,
        ],
        'solved' => false,
    ];
}

function lab_callbacks_path(): string
{
    return lab_storage_dir() . DIRECTORY_SEPARATOR . 'callbacks.jsonl';
}

function lab_append_callback(string $token, string $path): void
{
    $entry = [
        'token' => substr($token, 0, 120),
        'path' => $path,
        'time' => gmdate('c'),
        'remote' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    ];
    file_put_contents(
        lab_callbacks_path(),
        json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
}

function lab_callback_has_token(string $token): bool
{
    $path = lab_callbacks_path();
    if (!is_file($path)) {
        return false;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return false;
    }

    foreach (array_reverse($lines) as $line) {
        $entry = json_decode($line, true);
        if (is_array($entry) && ($entry['token'] ?? '') === $token) {
            return true;
        }
    }

    return false;
}

function lab_clear_callback_token(string $token): void
{
    $path = lab_callbacks_path();
    if (!is_file($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return;
    }

    $remaining = [];
    foreach ($lines as $line) {
        $entry = json_decode($line, true);
        if (is_array($entry) && ($entry['token'] ?? '') === $token) {
            continue;
        }
        $remaining[] = $line;
    }

    file_put_contents($path, $remaining === [] ? '' : implode(PHP_EOL, $remaining) . PHP_EOL, LOCK_EX);
}

function lab_logs_path(): string
{
    return lab_storage_dir() . DIRECTORY_SEPARATOR . 'requests.jsonl';
}

function lab_append_log(array $entry): void
{
    $entry['id'] = bin2hex(random_bytes(4));
    $entry['time'] = gmdate('c');
    $line = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    file_put_contents(lab_logs_path(), $line, FILE_APPEND | LOCK_EX);

    $path = lab_logs_path();
    if (is_file($path) && filesize($path) > 512000) {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($lines)) {
            $lines = array_slice($lines, -120);
            file_put_contents($path, implode(PHP_EOL, $lines) . PHP_EOL, LOCK_EX);
        }
    }
}

function lab_read_logs(int $limit = 40): array
{
    $path = lab_logs_path();
    if (!is_file($path)) {
        return [];
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return [];
    }

    $entries = [];
    foreach (array_slice($lines, -$limit) as $line) {
        $decoded = json_decode($line, true);
        if (is_array($decoded)) {
            $entries[] = $decoded;
        }
    }

    return array_reverse($entries);
}

function lab_clear_logs(): void
{
    $path = lab_logs_path();
    if (is_file($path)) {
        file_put_contents($path, '', LOCK_EX);
    }
}

function lab_base_headers(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
}

