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

function lab_vulnerable_filter(int $level, string $url): ?string
{
    $parts = lab_parse_http_url($url);
    $host = $parts['host'] ?? '';
    $port = $parts['port'] ?? 0;
    $rawParts = parse_url($url);
    $path = (string) ($parts['parts']['path'] ?? '');

    return match ($level) {
        1 => null,
        2 => preg_match('/(?:localhost|127\.0\.0\.1)/i', $url) === 1
            ? '黑名单命中：URL 中包含 localhost 或 127.0.0.1。'
            : null,
        3 => str_contains($url, 'shop.local')
            ? null
            : '白名单未命中：完整 URL 必须包含 shop.local。',
        4 => ($host !== '127.0.0.1' || $port !== LAB_REDIRECT_PORT)
            ? '首跳限制：URL 必须以 http://127.0.0.1:8083 开始。'
            : null,
        5 => !lab_is_rebind_host($host)
            ? '业务校验未通过：头像预览地址必须使用受测 CDN 域名。'
            : (lab_is_private_ip(LAB_REBIND_VALIDATION_IP)
                ? 'DNS 检查：首次解析结果指向内部地址，业务拒绝请求。'
                : null),
        6 => ($parts !== null && in_array($parts['scheme'], ['gopher', 'dict', 'ftp'], true))
            ? '危险协议：gopher、dict、ftp 已被拦截。'
            : null,
        7 => (($rawParts['user'] ?? '') !== 'shop.local')
            ? '域名白名单未命中：解析后的允许域必须是 shop.local。'
            : null,
        8 => preg_match('/(?:localhost|127\.0\.0\.1|2130706433|0x7f000001)/i', $url) === 1
            ? '高级黑名单命中：常见回环表示已被拦截。'
            : null,
        9 => !lab_is_dual_dns_host($host)
            ? 'DNS 白名单未命中：目标必须属于 dual-cdn.ssrf.lab。'
            : null,
        10 => ($host !== '127.0.0.1' || $port !== LAB_REDIRECT_PORT || $path !== '/redirect/chain')
            ? '首跳限制：只允许公开的多级重定向入口。'
            : null,
        11 => ($host !== '127.0.0.1' || $port !== LAB_INTERNAL_PORT)
            ? 'Webhook 目标必须位于实验内部服务的允许范围内。'
            : null,
        12 => ($host !== '127.0.0.1' || $port !== LAB_CALLBACK_PORT || $path !== '/callback')
            ? '回调地址未通过业务校验。'
            : null,
        13 => null,
        14 => str_contains($url, '169.254.169.254')
            ? '云元数据地址黑名单命中：169.254.169.254 已被拦截。'
            : (!lab_is_cloud_metadata_host($host)
                ? '元数据校验：只接受受支持的云厂商内部域名。'
                : null),
        15 => ($host !== '127.0.0.1' || $port !== LAB_CALLBACK_PORT || $path !== '/renderer-page')
            ? '预览请求只允许提交渲染器页面地址。'
            : null,
        16 => ($host !== '127.0.0.1' || $port !== LAB_CALLBACK_PORT || $path !== '/malicious-feed.xml')
            ? 'RSS 导入只允许提交受测订阅源地址。'
            : null,
        default => '未知关卡。',
    };
}

function lab_execute_file(int $level, string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $boundary = lab_boundary_check($level, $url);
    if (!$boundary['ok']) {
        return lab_result_error($boundary['reason'], $started, 'blocked');
    }

    $body = file_get_contents($boundary['path']);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);

    if ($body === false) {
        return lab_result_error('本地文件读取失败。', $started, 'error');
    }

    $body = substr($body, 0, 65536);

    return [
        'ok' => true,
        'blocked' => false,
        'validation' => ['decision' => 'allowed', 'message' => '协议黑名单未拦截 file://。'],
        'transport' => [
            'method' => 'GET',
            'target' => $url,
            'finalUrl' => $url,
            'resolvedIp' => null,
        ],
        'response' => [
            'status' => 200,
            'durationMs' => $duration,
            'bytes' => strlen($body),
            'body' => $body,
        ],
        'solved' => str_contains($body, $expectedFlag),
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

function lab_execute_http(int $level, string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $filterError = lab_vulnerable_filter($level, $url);
    if ($filterError !== null) {
        $result = lab_result_error($filterError, $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $boundary = lab_boundary_check($level, $url);
    if (!$boundary['ok']) {
        $result = lab_result_error($boundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $fetchUrl = $url;
    $resolvedIp = $boundary['normalizedHost'];
    $resolveEntries = [];

    if (lab_is_rebind_host($boundary['normalizedHost'])) {
        $resolvedIp = LAB_REBIND_CONNECTION_IP;
        $resolveEntries[] = $boundary['host'] . ':' . $boundary['port'] . ':' . LAB_REBIND_CONNECTION_IP;
    } elseif (lab_is_dual_dns_host($boundary['normalizedHost'])) {
        $resolvedIp = LAB_REBIND_CONNECTION_IP;
        $resolveEntries[] = $boundary['host'] . ':' . $boundary['port'] . ':' . LAB_REBIND_CONNECTION_IP;
    } elseif (lab_is_cloud_metadata_host($boundary['normalizedHost'])) {
        $resolvedIp = LAB_REBIND_CONNECTION_IP;
        $resolveEntries[] = $boundary['host'] . ':' . $boundary['port'] . ':' . LAB_REBIND_CONNECTION_IP;
    } elseif ($boundary['normalizedHost'] !== $boundary['host']) {
        $fetchUrl = lab_url_with_host($url, $boundary['normalizedHost']);
    }

    $ch = curl_init($fetchUrl);
    if ($ch === false) {
        return lab_result_error('无法初始化 HTTP 客户端。', $started);
    }

    $chunks = '';
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$chunks): int {
            if (strlen($chunks) < 65536) {
                $chunks .= substr($chunk, 0, 65536 - strlen($chunks));
            }
            return strlen($chunk);
        },
        CURLOPT_FOLLOWLOCATION => in_array($level, [4, 10], true),
        CURLOPT_MAXREDIRS => 4,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_USERAGENT => 'SSRF-Field-Lab/1.0',
        CURLOPT_HTTPHEADER => [
            'Accept: application/json,text/plain,text/html;q=0.9,*/*;q=0.8',
            'X-Lab-Fetch-Level: ' . $level,
        ],
    ]);

    if ($resolveEntries !== []) {
        curl_setopt($ch, CURLOPT_RESOLVE, $resolveEntries);
    }

    $ok = curl_exec($ch);
    $curlError = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $effectiveUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    $duration = (int) round((hrtime(true) - $started) / 1_000_000);

    if ($ok === false) {
        return [
            'ok' => false,
            'blocked' => false,
            'validation' => ['decision' => 'allowed', 'message' => '应用层校验通过，但 HTTP 请求失败。'],
            'transport' => [
                'method' => 'GET',
                'target' => $fetchUrl,
                'finalUrl' => $effectiveUrl,
                'resolvedIp' => $resolvedIp,
            ],
            'response' => [
                'status' => $status,
                'durationMs' => $duration,
                'bytes' => strlen($chunks),
                'body' => $curlError !== '' ? $curlError : '请求失败。',
            ],
            'solved' => false,
        ];
    }

    if ($effectiveUrl !== '' && $level !== 5) {
        $effectiveBoundary = lab_boundary_check($level, $effectiveUrl);
        if (!$effectiveBoundary['ok']) {
            return [
                'ok' => false,
                'blocked' => true,
                'validation' => [
                    'decision' => 'blocked',
                    'message' => '响应目标越过实验边界，结果已丢弃：' . $effectiveBoundary['reason'],
                ],
                'transport' => [
                    'method' => 'GET',
                    'target' => $fetchUrl,
                    'finalUrl' => $effectiveUrl,
                    'resolvedIp' => $resolvedIp,
                ],
                'response' => [
                    'status' => $status,
                    'durationMs' => $duration,
                    'bytes' => 0,
                    'body' => '实验边界拦截了跳转目标。',
                ],
                'solved' => false,
            ];
        }
    }

    return [
        'ok' => true,
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => match ($level) {
                5 => '头像预览业务首次解析返回 203.0.113.77，安全校验通过。',
                9 => 'DNS 校验只查看了第一条公网 A 记录，安全校验通过。',
                10 => '首跳重定向地址通过校验，客户端开始自动跟随跳转。',
                14 => '标准元数据 IP 被拦截，但云厂商内部域名未被识别。',
                default => '应用层校验通过。',
            },
        ],
        'transport' => [
            'method' => 'GET',
            'target' => $fetchUrl,
            'finalUrl' => $effectiveUrl,
            'resolvedIp' => $resolvedIp,
        ],
        'response' => [
            'status' => $status,
            'durationMs' => $duration,
            'bytes' => strlen($chunks),
            'body' => $chunks,
        ],
        'solved' => str_contains($chunks, $expectedFlag),
    ];
}

function lab_simple_http_get(string $url, int $level, bool $followRedirects = false): array
{
    $started = hrtime(true);
    $ch = curl_init($url);
    if ($ch === false) {
        return [
            'ok' => false,
            'body' => '无法初始化 HTTP 客户端。',
            'status' => 0,
            'error' => 'curl_init failed',
            'effectiveUrl' => '',
            'durationMs' => 0,
        ];
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => $followRedirects,
        CURLOPT_MAXREDIRS => 4,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_USERAGENT => 'SSRF-Field-Lab/1.1',
        CURLOPT_HTTPHEADER => [
            'Accept: application/json,text/plain,text/html,application/xml;q=0.9,*/*;q=0.8',
            'X-Lab-Fetch-Level: ' . $level,
        ],
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $effectiveUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    return [
        'ok' => $body !== false,
        'body' => is_string($body) ? substr($body, 0, 65536) : '',
        'status' => $status,
        'error' => $error,
        'effectiveUrl' => $effectiveUrl,
        'durationMs' => (int) round((hrtime(true) - $started) / 1_000_000),
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

function lab_execute_header_ssrf(string $baseUrl, array $context, string $expectedFlag): array
{
    $started = hrtime(true);
    $parts = lab_parse_http_url($baseUrl);
    if ($parts === null) {
        return lab_result_error('Webhook 基地址格式无效。', $started, 'blocked');
    }

    $path = (string) ($parts['parts']['path'] ?? '');
    if ($parts['host'] !== '127.0.0.1' || $parts['port'] !== LAB_APP_PORT || $path !== '/webhook/test') {
        return lab_result_error('Webhook 基地址必须是 http://127.0.0.1:8080/webhook/test。', $started, 'blocked');
    }

    $headerHost = trim((string) ($context['headerHost'] ?? ''));
    if ($headerHost === '') {
        return lab_result_error('请输入 X-Forwarded-Host 的值。', $started, 'blocked');
    }

    $target = 'http://' . $headerHost . '/internal/webhook';
    $boundary = lab_boundary_check(11, $target);
    if (!$boundary['ok']) {
        $result = lab_result_error($boundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $target;
        return $result;
    }

    $fetch = lab_simple_http_get($target, 11);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);
    if (!$fetch['ok']) {
        $result = lab_result_error($fetch['error'] ?: 'Webhook 请求失败。', $started);
        $result['transport']['target'] = $target;
        return $result;
    }

    return [
        'ok' => true,
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => 'Webhook 基地址通过校验，但 X-Forwarded-Host 被直接拼入内部请求目标。',
        ],
        'transport' => [
            'method' => 'GET',
            'target' => $target,
            'finalUrl' => $fetch['effectiveUrl'],
            'resolvedIp' => '127.0.0.1',
        ],
        'response' => [
            'status' => $fetch['status'],
            'durationMs' => $duration,
            'bytes' => strlen($fetch['body']),
            'body' => $fetch['body'],
        ],
        'solved' => str_contains($fetch['body'], $expectedFlag),
    ];
}

function lab_execute_blind_ssrf(string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $filterError = lab_vulnerable_filter(12, $url);
    if ($filterError !== null) {
        $result = lab_result_error($filterError, $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $boundary = lab_boundary_check(12, $url);
    if (!$boundary['ok']) {
        $result = lab_result_error($boundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    $token = substr(trim((string) ($query['token'] ?? 'blind-level12')), 0, 120);
    lab_clear_callback_token($token);

    $fetch = lab_simple_http_get($url, 12);
    usleep(60000);
    $hit = lab_callback_has_token($token);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);
    $body = $hit
        ? '盲 SSRF 已确认：回调服务收到了业务服务器发起的请求。业务端没有回显目标响应。'
        : '请求已由业务服务器发出，但尚未在回调服务中观察到匹配记录。';

    return [
        'ok' => $fetch['ok'],
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => $hit ? '外部回调监听器确认收到请求，响应正文未被业务回显。' : '业务请求已发出，回调证据尚未出现。',
        ],
        'transport' => [
            'method' => 'GET',
            'target' => $url,
            'finalUrl' => $fetch['effectiveUrl'],
            'resolvedIp' => '127.0.0.1',
        ],
        'response' => [
            'status' => $fetch['status'],
            'durationMs' => $duration,
            'bytes' => 0,
            'body' => $body,
        ],
        'solved' => $hit,
    ];
}

function lab_execute_gopher_ssrf(string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $boundary = lab_boundary_check(13, $url);
    if (!$boundary['ok']) {
        return lab_result_error($boundary['reason'], $started, 'blocked');
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return lab_result_error('无法初始化 gopher 客户端。', $started);
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_PROTOCOLS => CURLPROTO_GOPHER,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);

    if ($body === false) {
        return lab_result_error($error !== '' ? $error : 'gopher 请求失败。', $started);
    }

    $body = substr((string) $body, 0, 65536);

    return [
        'ok' => true,
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => 'HTTP 客户端允许 gopher 协议，原始字节流被发送到模拟 TCP 服务。',
        ],
        'transport' => [
            'method' => 'GOPHER',
            'target' => $url,
            'finalUrl' => $url,
            'resolvedIp' => '127.0.0.1',
        ],
        'response' => [
            'status' => 200,
            'durationMs' => $duration,
            'bytes' => strlen($body),
            'body' => $body,
        ],
        'solved' => str_contains($body, $expectedFlag),
    ];
}

function lab_execute_renderer_ssrf(string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $filterError = lab_vulnerable_filter(15, $url);
    if ($filterError !== null) {
        $result = lab_result_error($filterError, $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $boundary = lab_boundary_check(15, $url);
    if (!$boundary['ok']) {
        $result = lab_result_error($boundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $page = lab_simple_http_get($url, 15);
    if (!$page['ok'] || preg_match('/<img\b[^>]*\bsrc=["\']([^"\']+)["\']/i', $page['body'], $match) !== 1) {
        return lab_result_error('渲染器页面没有返回可加载的图片资源。', $started);
    }

    $resourceUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resourceBoundary = lab_boundary_check(15, $resourceUrl);
    if (!$resourceBoundary['ok']) {
        $result = lab_result_error($resourceBoundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $resource = lab_simple_http_get($resourceUrl, 15);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);

    return [
        'ok' => $resource['ok'],
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => '首跳渲染器页面通过校验，但图片渲染器又自动请求了页面内的内网资源。',
        ],
        'transport' => [
            'method' => 'GET',
            'target' => $url,
            'finalUrl' => $resourceUrl,
            'resolvedIp' => '127.0.0.1',
        ],
        'response' => [
            'status' => $resource['status'],
            'durationMs' => $duration,
            'bytes' => strlen($resource['body']),
            'body' => $resource['body'],
        ],
        'solved' => str_contains($resource['body'], $expectedFlag),
    ];
}

function lab_execute_rss_ssrf(string $url, string $expectedFlag): array
{
    $started = hrtime(true);
    $filterError = lab_vulnerable_filter(16, $url);
    if ($filterError !== null) {
        $result = lab_result_error($filterError, $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $boundary = lab_boundary_check(16, $url);
    if (!$boundary['ok']) {
        $result = lab_result_error($boundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $feed = lab_simple_http_get($url, 16);
    if (!$feed['ok'] || preg_match('/<enclosure\b[^>]*\burl=["\']([^"\']+)["\']/i', $feed['body'], $match) !== 1) {
        return lab_result_error('RSS 订阅源没有返回可导入的 enclosure 地址。', $started);
    }

    $resourceUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resourceBoundary = lab_boundary_check(16, $resourceUrl);
    if (!$resourceBoundary['ok']) {
        $result = lab_result_error($resourceBoundary['reason'], $started, 'blocked');
        $result['transport']['target'] = $url;
        return $result;
    }

    $resource = lab_simple_http_get($resourceUrl, 16);
    $duration = (int) round((hrtime(true) - $started) / 1_000_000);

    return [
        'ok' => $resource['ok'],
        'blocked' => false,
        'validation' => [
            'decision' => 'allowed',
            'message' => 'RSS 地址通过校验，但导入器随后自动抓取了订阅内容中的 enclosure 内网地址。',
        ],
        'transport' => [
            'method' => 'GET',
            'target' => $url,
            'finalUrl' => $resourceUrl,
            'resolvedIp' => '127.0.0.1',
        ],
        'response' => [
            'status' => $resource['status'],
            'durationMs' => $duration,
            'bytes' => strlen($resource['body']),
            'body' => $resource['body'],
        ],
        'solved' => str_contains($resource['body'], $expectedFlag),
    ];
}

function lab_execute_probe(int $level, string $url, string $expectedFlag, array $context = []): array
{
    if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'file') {
        return lab_execute_file($level, $url, $expectedFlag);
    }

    if ($level === 11) {
        return lab_execute_header_ssrf($url, $context, $expectedFlag);
    }

    if ($level === 12) {
        return lab_execute_blind_ssrf($url, $expectedFlag);
    }

    if ($level === 13) {
        return lab_execute_gopher_ssrf($url, $expectedFlag);
    }

    if ($level === 15) {
        return lab_execute_renderer_ssrf($url, $expectedFlag);
    }

    if ($level === 16) {
        return lab_execute_rss_ssrf($url, $expectedFlag);
    }

    return lab_execute_http($level, $url, $expectedFlag);
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

