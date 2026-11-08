<?php

declare(strict_types=1);

/**
 * SSRF Field Lab 前端/API 入口。
 *
 * 这是一个“单入口”PHP 应用：
 * 1. 浏览器访问 8080 时，返回教学页面和 /api/* 接口。
 * 2. PHP 内置服务器还可以通过 router-internal.php 等文件，
 *    以不同角色启动内部服务、元数据服务、回调服务。
 * 3. LAB_ROLE 决定当前进程扮演哪一种服务。
 */
require_once dirname(__DIR__) . '/src/bootstrap.php';

// 只取 URL 的 path 部分，例如 /api/probe?debug=1 -> /api/probe。
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$role = LAB_ROLE;

// 所有服务共用的健康检查，便于 start.ps1 判断进程是否启动成功。
if ($path === '/api/health') {
    lab_json_response([
        'ok' => true,
        'role' => $role,
        'service' => match ($role) {
            'internal' => 'SSRF Lab Internal Admin',
            'metadata' => 'SSRF Lab Mock Metadata',
            'callback' => 'SSRF Lab Callback Listener',
            default => 'SSRF Field Lab',
        },
        'time' => gmdate('c'),
    ]);
}

// 根据启动角色分发到不同服务。每个 handler 内部都会直接结束请求。
if ($role === 'internal') {
    lab_handle_internal($path, $method);
}

if ($role === 'metadata') {
    lab_handle_metadata($path, $method);
}

if ($role === 'redirect') {
    lab_handle_redirect($path, $method);
}

if ($role === 'callback') {
    lab_handle_callback($path, $method);
}

lab_handle_app($path, $method);

function lab_handle_internal(string $path, string $method): never
{
    if ($method !== 'GET') {
        lab_json_response(['error' => 'Method not allowed'], 405);
    }

    // 自定义请求头由主站发送，用来判断当前是哪一个教学关卡。
    $fetchLevel = (int) ($_SERVER['HTTP_X_LAB_FETCH_LEVEL'] ?? 0);
    $flag = match ($fetchLevel) {
        2 => 'FLAG{SSRF_BLACKLIST_IP_ENCODING}',
        4 => 'FLAG{SSRF_REDIRECT_CHAIN}',
        10 => 'FLAG{SSRF_MULTIHOP_REDIRECT}',
        default => 'FLAG{SSRF_INTERNAL_ADMIN_ACCESS}',
    };
    // 去掉末尾斜杠，避免 /admin 和 /admin/ 被当成两个完全不同的路由。
    $path = rtrim($path, '/') ?: '/';

    if ($path === '/admin') {
        lab_json_response([
            'service' => 'internal-admin',
            'message' => 'Internal operations console. This endpoint is not meant for public browsers.',
            'flag' => $flag,
            'deployment' => [
                'environment' => 'production',
                'region' => 'cn-local-1',
                'build' => '2026.11.06-lab',
            ],
        ]);
    }

    if ($path === '/internal/debug') {
        lab_json_response([
            'service' => 'internal-debug',
            'message' => 'Debug endpoint reached through an application-layer filter bypass.',
            'requested_source' => $_GET['source'] ?? null,
            'flag' => 'FLAG{SSRF_KEYWORD_FILTER_BYPASS}',
        ]);
    }

    if ($path === '/internal/parser') {
        lab_json_response([
            'service' => 'internal-parser-target',
            'message' => 'Userinfo component confused with the real request host.',
            'flag' => 'FLAG{SSRF_URL_PARSER_CONFUSION}',
        ]);
    }

    if ($path === '/internal/encoding') {
        lab_json_response([
            'service' => 'internal-address-encoding-target',
            'message' => 'The blacklist compared text, but the socket connected to loopback.',
            'flag' => 'FLAG{SSRF_ADVANCED_IP_ENCODING}',
        ]);
    }

    if ($path === '/internal/dns-mixed') {
        lab_json_response([
            'service' => 'internal-mixed-dns-target',
            'message' => 'The safety check read only the first DNS answer.',
            'flag' => 'FLAG{SSRF_MIXED_DNS_ANSWERS}',
        ]);
    }

    if ($path === '/internal/webhook') {
        lab_json_response([
            'service' => 'internal-webhook-target',
            'message' => 'The webhook base URL was trusted, but the forwarded host was not.',
            'flag' => 'FLAG{SSRF_HEADER_DRIVEN}',
        ]);
    }

    if ($path === '/internal/renderer') {
        lab_json_response([
            'service' => 'internal-renderer-target',
            'message' => 'The page renderer followed a secondary image resource.',
            'flag' => 'FLAG{SSRF_RENDERER_SECONDARY_REQUEST}',
        ]);
    }

    if ($path === '/internal/rss') {
        lab_json_response([
            'service' => 'internal-rss-target',
            'message' => 'The RSS importer followed an enclosure from feed content.',
            'flag' => 'FLAG{SSRF_RSS_IMPORT}',
        ]);
    }

    if ($path === '/') {
        lab_json_response([
            'service' => 'internal-admin',
            'endpoints' => [
                '/admin',
                '/internal/debug',
                '/internal/parser',
                '/internal/encoding',
                '/internal/dns-mixed',
                '/internal/webhook',
                '/internal/renderer',
                '/internal/rss',
            ],
        ]);
    }

    lab_json_response(['error' => 'Internal endpoint not found'], 404);
}

function lab_handle_metadata(string $path, string $method): never
{
    if ($method !== 'GET') {
        lab_json_response(['error' => 'Method not allowed'], 405);
    }

    // 模拟云元数据服务。真实元数据通常保存实例身份和临时凭据。
    $path = rtrim($path, '/') ?: '/';

    if ($path === '/latest/meta-data/iam/security-credentials/lab-role') {
        $fetchLevel = (int) ($_SERVER['HTTP_X_LAB_FETCH_LEVEL'] ?? 0);
        $tokenFlag = $fetchLevel === 5
            ? 'FLAG{SSRF_DNS_REBINDING}'
            : 'FLAG{SSRF_DIRECT_METADATA_ACCESS}';

        lab_json_response([
            'Code' => 'Success',
            'LastUpdated' => '2026-11-06T00:00:00Z',
            'Type' => 'AWS-HMAC',
            'AccessKeyId' => 'ASIA_LAB_ONLY_DEMO',
            'SecretAccessKey' => 'not-a-real-secret',
            'Token' => $tokenFlag,
            'Expiration' => '2026-11-06T06:00:00Z',
            'Note' => 'Mock credentials for the local SSRF lab. Do not use against real metadata services.',
        ]);
    }

    if ($path === '/computeMetadata/v1/instance/service-accounts/default/token') {
        $fetchLevel = (int) ($_SERVER['HTTP_X_LAB_FETCH_LEVEL'] ?? 0);
        lab_json_response([
            'service' => 'mock-gcp-metadata',
            'access_token' => 'ya29.lab-only-token',
            'expires_in' => 3600,
            'flag' => $fetchLevel === 14
                ? 'FLAG{SSRF_CLOUD_METADATA_VARIANT}'
                : 'FLAG{SSRF_DIRECT_METADATA_ACCESS}',
        ]);
    }

    if ($path === '/latest/meta-data/instance-id') {
        lab_text_response('ssrf-lab-instance-01');
    }

    if ($path === '/') {
        lab_json_response([
            'service' => 'mock-cloud-metadata',
            'namespace' => '/latest/meta-data',
            'warning' => 'This service exists only inside the local SSRF lab.',
        ]);
    }

    lab_text_response('Not found', 404);
}

function lab_handle_redirect(string $path, string $method): never
{
    if ($path === '/api/health') {
        lab_json_response([
            'ok' => true,
            'role' => 'redirect',
            'service' => 'SSRF Lab Public Redirect',
            'time' => gmdate('c'),
        ]);
    }

    // 单级重定向：只发送一个 302，由 HTTP 客户端继续请求 Location。
    if ($path === '/redirect' && $method === 'GET') {
        $target = trim((string) ($_GET['to'] ?? ''));
        $boundary = lab_boundary_check(4, $target);
        if ($target === '' || !$boundary['ok']) {
            lab_text_response('Invalid redirect target. The lab redirector only accepts local lab URLs.', 400);
        }

        header('Cache-Control: no-store');
        header('Location: ' . $target, true, 302);
        exit;
    }

    // 多级重定向：chain 跳到 final，final 再跳到真正的内部目标。
    if ($path === '/redirect/chain' && $method === 'GET') {
        $target = trim((string) ($_GET['to'] ?? ''));
        $boundary = lab_boundary_check(10, $target);
        if ($target === '' || !$boundary['ok']) {
            lab_text_response('Invalid chained redirect target.', 400);
        }

        header('Cache-Control: no-store');
        header('Location: /redirect/final?to=' . rawurlencode($target), true, 302);
        exit;
    }

    if ($path === '/redirect/final' && $method === 'GET') {
        $target = trim((string) ($_GET['to'] ?? ''));
        $boundary = lab_boundary_check(10, $target);
        if ($target === '' || !$boundary['ok']) {
            lab_text_response('Invalid final redirect target.', 400);
        }

        header('Cache-Control: no-store');
        header('Location: ' . $target, true, 302);
        exit;
    }

    if ($path === '/') {
        lab_text_response('Public redirect service. Try /redirect?to=<local-lab-url>.');
    }

    lab_text_response('Not found', 404);
}

function lab_handle_callback(string $path, string $method): never
{
    if ($path === '/api/health') {
        lab_json_response([
            'ok' => true,
            'role' => 'callback',
            'service' => 'SSRF Lab Callback Listener',
            'time' => gmdate('c'),
        ]);
    }

    // 盲 SSRF 回调端点：返回 204，不向业务端回显任何目标内容。
    if ($path === '/callback' && $method === 'GET') {
        $token = trim((string) ($_GET['token'] ?? 'callback'));
        lab_append_callback($token, $path);
        http_response_code(204);
        header('Cache-Control: no-store');
        exit;
    }

    // 返回一个带 <img src="..."> 的页面，模拟渲染器后续加载子资源。
    if ($path === '/renderer-page' && $method === 'GET') {
        $target = trim((string) ($_GET['target'] ?? ''));
        $boundary = lab_boundary_check(15, $target);
        if ($target === '' || !$boundary['ok']) {
            lab_text_response('Invalid render resource target.', 400);
        }

        $safeTarget = htmlspecialchars($target, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        lab_text_response(
            '<!doctype html><html><body><article class="preview"><h1>Shared link preview</h1><img src="' .
            $safeTarget .
            '" alt="preview"></article></body></html>',
            200,
            'text/html; charset=utf-8'
        );
    }

    // 返回一个 RSS 文档，其中 enclosure 指向内部服务。
    if ($path === '/malicious-feed.xml' && $method === 'GET') {
        lab_text_response(
            '<?xml version="1.0" encoding="UTF-8"?>' .
            '<rss version="2.0"><channel><title>Partner updates</title>' .
            '<item><title>Weekly partner note</title>' .
            '<enclosure url="http://127.0.0.1:8081/internal/rss" type="application/json" length="1"/>' .
            '</item></channel></rss>',
            200,
            'application/rss+xml; charset=utf-8'
        );
    }

    lab_text_response('Callback listener ready.', 200);
}

function lab_handle_app(string $path, string $method): never
{
    // 浏览器加载页面时读取关卡配置。successFlag 不下发给前端，避免直接看到答案。
    if ($path === '/api/bootstrap' && $method === 'GET') {
        $challenges = lab_challenges();
        $publicChallenges = [];

        foreach ($challenges as $id => $challenge) {
            unset($challenge['successFlag']);
            $publicChallenges[] = $challenge;
        }

        lab_json_response([
            'lab' => [
                'name' => 'SSRF Field Lab',
                'version' => '2.0.0',
                'boundary' => '仅允许访问 127.0.0.0/8、教学端口 8080-8084 与模拟 TCP 6380',
            ],
            'challenges' => $publicChallenges,
            'defense' => lab_defense_guide(),
            'services' => [
                'app' => 'http://127.0.0.1:8080',
                'internal' => 'http://127.0.0.1:8081',
                'metadata' => 'http://127.0.0.1:8082',
                'redirect' => 'http://127.0.0.1:8083',
                'callback' => 'http://127.0.0.1:8084',
                'gopher' => '127.0.0.1:6380',
            ],
        ]);
    }

    // 用户点击“查看解法”后才返回步骤和修复建议。
    if ($path === '/api/solution' && $method === 'GET') {
        $level = (int) ($_GET['level'] ?? 0);
        $challenges = lab_challenges();
        if (!isset($challenges[$level])) {
            lab_json_response(['error' => '未知关卡'], 404);
        }

        lab_json_response([
            'level' => $level,
            'steps' => $challenges[$level]['answerSteps'],
            'defense' => $challenges[$level]['defense'],
        ]);
    }

    // 核心实验接口：接收关卡、URL 和可选 Header 字段，并交给执行器。
    if ($path === '/api/probe' && $method === 'POST') {
        $input = lab_read_json_body();
        $level = (int) ($input['level'] ?? 0);
        $url = trim((string) ($input['url'] ?? ''));
        // Header 驱动等关卡需要额外字段；普通关卡会得到空数组。
        $fields = is_array($input['fields'] ?? null) ? $input['fields'] : [];
        $challenges = lab_challenges();

        if (!isset($challenges[$level])) {
            lab_json_response(['error' => '未知关卡'], 422);
        }

        if ($url === '') {
            lab_json_response(['error' => '请输入 URL'], 422);
        }

        if (strlen($url) > 2048) {
            lab_json_response(['error' => 'URL 长度不能超过 2048 字符'], 422);
        }

        $started = microtime(true);
        $result = lab_execute_probe($level, $url, $challenges[$level]['successFlag'], $fields);
        $elapsed = (int) round((microtime(true) - $started) * 1000);

        lab_append_log([
            'level' => $level,
            'levelTitle' => $challenges[$level]['title'],
            'url' => $url,
            'decision' => $result['validation']['decision'],
            'message' => $result['validation']['message'],
            'status' => $result['response']['status'],
            'durationMs' => $result['response']['durationMs'],
            'finalUrl' => $result['transport']['finalUrl'],
            'solved' => $result['solved'],
        ]);

        lab_json_response([
            'level' => $level,
            'result' => $result,
            'elapsedMs' => $elapsed,
        ]);
    }

    // 请求轨迹面板每隔几秒读取一次最近的实验请求。
    if ($path === '/api/logs' && $method === 'GET') {
        lab_json_response(['logs' => lab_read_logs(40)]);
    }

    if ($path === '/api/clear-logs' && $method === 'POST') {
        lab_clear_logs();
        lab_json_response(['ok' => true]);
    }

    if ($path === '/' || $path === '/index.php') {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        readfile(__DIR__ . '/lab.html');
        exit;
    }

    if (str_starts_with($path, '/api/')) {
        lab_json_response(['error' => 'API endpoint not found'], 404);
    }

    lab_text_response('Not found', 404);
}

