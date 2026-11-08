<?php

declare(strict_types=1);

/**
 * 实验出网网关。
 *
 * 这一层只负责三件事：
 * 1. 强制实验安全边界（回环地址、教学端口、file/gopher 白名单）；
 * 2. 把数字/八进制等主机写法归一化，模拟真实 HTTP 客户端；
 * 3. 执行请求并在重定向后复查最终目标。
 *
 * 它不包含任何"关卡校验"逻辑；每个业务 handler 自己决定传什么 URL 进来。
 */

function lab_egress_duration(int $started): int
{
    return (int) round((hrtime(true) - $started) / 1_000_000);
}

function lab_egress_blocked(int $started, string $reason, string $target = '', string $method = 'GET'): array
{
    return [
        'ok' => false,
        'blocked' => true,
        'method' => $method,
        'reason' => $reason,
        'status' => 0,
        'body' => '',
        'target' => $target,
        'finalUrl' => '',
        'resolvedIp' => null,
        'bytes' => 0,
        'durationMs' => lab_egress_duration($started),
        'error' => '',
    ];
}

function lab_egress_fetch_failed(int $started, string $target, string $method, int $status, string $error, int $durationMs, ?string $resolvedIp = null): array
{
    return [
        'ok' => false,
        'blocked' => false,
        'method' => $method,
        'reason' => null,
        'status' => $status,
        'body' => $error !== '' ? $error : '请求失败。',
        'target' => $target,
        'finalUrl' => '',
        'resolvedIp' => $resolvedIp,
        'bytes' => 0,
        'durationMs' => $durationMs,
        'error' => $error,
    ];
}

/**
 * @param array{
 *   followRedirects?: bool,
 *   maxRedirects?: int,
 *   resolveIp?: ?string,
 *   returnBody?: bool,
 *   extraHeaders?: string[],
 *   timeout?: int,
 *   userAgent?: string
 * } $options
 */
function lab_egress_http(int $level, string $url, array $options = []): array
{
    $started = hrtime(true);
    $opts = array_merge([
        'followRedirects' => false,
        'maxRedirects' => 4,
        'resolveIp' => null,
        'returnBody' => true,
        'extraHeaders' => [],
        'timeout' => 4,
        'userAgent' => 'SSRF-Field-Lab/2.0',
    ], $options);

    $boundary = lab_boundary_check($level, $url);
    if (!$boundary['ok']) {
        return lab_egress_blocked($started, (string) ($boundary['reason'] ?? '实验边界拦截。'), $url);
    }

    if (($boundary['kind'] ?? '') !== 'http') {
        return lab_egress_blocked($started, 'HTTP 客户端仅支持 http/https 目标。', $url);
    }

    $fetchUrl = $url;
    $resolvedIp = $boundary['normalizedHost'];
    $resolveEntries = [];

    if (
        lab_is_rebind_host($boundary['normalizedHost'])
        || lab_is_dual_dns_host($boundary['normalizedHost'])
        || lab_is_cloud_metadata_host($boundary['normalizedHost'])
    ) {
        $resolvedIp = (string) ($opts['resolveIp'] ?? '127.0.0.1');
        $resolveEntries[] = $boundary['host'] . ':' . $boundary['port'] . ':' . $resolvedIp;
    } elseif ($boundary['normalizedHost'] !== $boundary['host']) {
        $fetchUrl = lab_url_with_host($url, $boundary['normalizedHost']);
        $resolvedIp = $boundary['normalizedHost'];
    }

    $chunks = '';
    $headers = array_merge([
        'Accept: application/json,text/plain,text/html,application/xml;q=0.9,*/*;q=0.8',
        'X-Lab-Fetch-Level: ' . $level,
    ], $opts['extraHeaders']);

    $ch = curl_init($fetchUrl);
    if ($ch === false) {
        return lab_egress_fetch_failed($started, $fetchUrl, 'GET', 0, '无法初始化 HTTP 客户端。', lab_egress_duration($started), $resolvedIp);
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$chunks, $opts): int {
            if ($opts['returnBody'] && strlen($chunks) < 65536) {
                $chunks .= substr($chunk, 0, 65536 - strlen($chunks));
            }

            return strlen($chunk);
        },
        CURLOPT_FOLLOWLOCATION => (bool) $opts['followRedirects'],
        CURLOPT_MAXREDIRS => max(1, (int) $opts['maxRedirects']),
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => max(1, (int) $opts['timeout']),
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_USERAGENT => (string) $opts['userAgent'],
        CURLOPT_HTTPHEADER => $headers,
    ]);

    if ($resolveEntries !== []) {
        curl_setopt($ch, CURLOPT_RESOLVE, $resolveEntries);
    }

    $ok = curl_exec($ch);
    $curlError = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $effectiveUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    $durationMs = lab_egress_duration($started);

    if ($ok === false) {
        return lab_egress_fetch_failed($started, $fetchUrl, 'GET', $status, $curlError, $durationMs, $resolvedIp);
    }

    if ($effectiveUrl !== '') {
        $effectiveBoundary = lab_boundary_check($level, $effectiveUrl);
        if (!$effectiveBoundary['ok']) {
            return lab_egress_blocked(
                $started,
                '响应目标越过实验边界，结果已丢弃：' . (string) ($effectiveBoundary['reason'] ?? '未知原因'),
                $fetchUrl
            );
        }
    }

    return [
        'ok' => true,
        'blocked' => false,
        'method' => 'GET',
        'reason' => null,
        'status' => $status,
        'body' => $chunks,
        'target' => $fetchUrl,
        'finalUrl' => $effectiveUrl,
        'resolvedIp' => $resolvedIp,
        'bytes' => strlen($chunks),
        'durationMs' => $durationMs,
        'error' => '',
    ];
}

function lab_egress_gopher(int $level, string $url): array
{
    $started = hrtime(true);
    $boundary = lab_boundary_check($level, $url);
    if (!$boundary['ok']) {
        return lab_egress_blocked($started, (string) ($boundary['reason'] ?? '实验边界拦截。'), $url, 'GOPHER');
    }

    if (($boundary['kind'] ?? '') !== 'gopher') {
        return lab_egress_blocked($started, 'Gopher 客户端只接受 gopher:// 目标。', $url, 'GOPHER');
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return lab_egress_fetch_failed($started, $url, 'GOPHER', 0, '无法初始化 gopher 客户端。', lab_egress_duration($started), $boundary['host']);
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_PROTOCOLS => CURLPROTO_GOPHER,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_USERAGENT => 'SSRF-Field-Lab/2.0',
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $durationMs = lab_egress_duration($started);
    curl_close($ch);

    if ($body === false) {
        return lab_egress_fetch_failed($started, $url, 'GOPHER', 0, $error, $durationMs, $boundary['host']);
    }

    $body = substr((string) $body, 0, 65536);

    return [
        'ok' => true,
        'blocked' => false,
        'method' => 'GOPHER',
        'reason' => null,
        'status' => 200,
        'body' => $body,
        'target' => $url,
        'finalUrl' => $url,
        'resolvedIp' => $boundary['host'],
        'bytes' => strlen($body),
        'durationMs' => $durationMs,
        'error' => '',
    ];
}

function lab_egress_read_file(int $level, string $url): array
{
    $started = hrtime(true);
    $boundary = lab_boundary_check($level, $url);
    if (!$boundary['ok']) {
        return lab_egress_blocked($started, (string) ($boundary['reason'] ?? '实验边界拦截。'), $url, 'FILE');
    }

    if (($boundary['kind'] ?? '') !== 'file') {
        return lab_egress_blocked($started, '文件客户端只接受 file:// 目标。', $url, 'FILE');
    }

    $body = file_get_contents((string) $boundary['path']);
    $durationMs = lab_egress_duration($started);

    if ($body === false) {
        return lab_egress_fetch_failed($started, $url, 'FILE', 0, '本地文件读取失败。', $durationMs);
    }

    $body = substr($body, 0, 65536);

    return [
        'ok' => true,
        'blocked' => false,
        'method' => 'FILE',
        'reason' => null,
        'status' => 200,
        'body' => $body,
        'target' => $url,
        'finalUrl' => $url,
        'resolvedIp' => null,
        'bytes' => strlen($body),
        'durationMs' => $durationMs,
        'error' => '',
    ];
}
