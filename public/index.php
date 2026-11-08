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

// 只取 URL 的 path 部分，例如 /products/import-image?debug=1 -> /products/import-image。
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
if ($role === 'target') {
    lab_handle_target($path, $method);
}

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

function lab_handle_target(string $path, string $method): never
{
    if ($method !== 'GET') {
        lab_json_response(['error' => 'Method not allowed'], 405);
    }

    // 有回显验证：根路径返回一段 MD5。
    if ($path === '/' || $path === '/index.php') {
        $md5 = md5('ssrf-lab-target-2026');
        lab_text_response("md5={$md5}\n", 200);
    }

    // 无回显验证：host 参数触发真实 DNS 查询；
    // 可选 host=ssrf-lab&port=8081&path=/admin 让目标访问靶场内部服务。
    if ($path === '/index') {
        $host = trim((string) ($_GET['host'] ?? ''));
        if ($host === '' || preg_match('/^[a-z0-9._-]+$/i', $host) !== 1) {
            lab_json_response(['error' => 'host is required'], 422);
        }

        // 只做 A 查询：dnslog 只需要看到一次域名解析请求，同时避免 AAAA 冷查询拖慢响应。
        $records = @dns_get_record($host, DNS_A);
        $resolved = [];
        if (is_array($records)) {
            foreach ($records as $record) {
                if (isset($record['ip'])) {
                    $resolved[] = (string) $record['ip'];
                }
                if (isset($record['ipv6'])) {
                    $resolved[] = (string) $record['ipv6'];
                }
            }
        }

        $response = [
            'ok' => true,
            'dns_queried' => true,
            'host' => $host,
            'resolved_ips' => array_values(array_unique($resolved)),
        ];

        $port = (int) ($_GET['port'] ?? 0);
        $fetchPath = (string) ($_GET['path'] ?? '');
        if ($port > 0) {
            $allowedPort = in_array($port, [8081, 8082, 8083, 8084], true);
            $validPath = $fetchPath !== '' && $fetchPath[0] === '/' && preg_match('/[\r\n]/', $fetchPath) !== 1;
            if ($host !== 'ssrf-lab' || !$allowedPort || !$validPath) {
                $response['internal_fetch'] = ['error' => 'internal fetch target is not allowed'];
            } else {
                $fetchUrl = 'http://' . $host . ':' . $port . $fetchPath;
                $ch = curl_init($fetchUrl);
                if ($ch === false) {
                    $response['internal_fetch'] = ['error' => 'curl init failed'];
                } else {
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_CONNECTTIMEOUT => 2,
                        CURLOPT_TIMEOUT => 4,
                        CURLOPT_PROXY => '',
                        CURLOPT_NOPROXY => '*',
                        CURLOPT_HTTPHEADER => ['X-Lab-Fetch-Level: 12'],
                    ]);
                    $body = curl_exec($ch);
                    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                    $error = curl_error($ch);
                    curl_close($ch);
                    $response['internal_fetch'] = [
                        'url' => $fetchUrl,
                        'status' => $status,
                        'bytes' => is_string($body) ? strlen($body) : 0,
                        'error' => $error,
                    ];
                }
            }
        }

        lab_json_response($response);
    }

    lab_json_response(['error' => 'Target endpoint not found'], 404);
}

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

    // 返回一个 RSS 文档，其中的 enclosure 默认指向内部服务。
    // 允许通过 ?enclosure= 指定其他目标，用来模拟攻击者控制的订阅内容。
    if ($path === '/malicious-feed.xml' && $method === 'GET') {
        $enclosure = trim((string) ($_GET['enclosure'] ?? 'http://127.0.0.1:8081/internal/rss'));
        $boundary = lab_boundary_check(16, $enclosure);
        if ($enclosure === '' || !$boundary['ok']) {
            lab_text_response('Invalid enclosure target.', 400);
        }

        $safeEnclosure = htmlspecialchars($enclosure, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        lab_text_response(
            '<?xml version="1.0" encoding="UTF-8"?>' .
            '<rss version="2.0"><channel><title>Partner updates</title>' .
            '<item><title>Weekly partner note</title>' .
            '<enclosure url="' . $safeEnclosure . '" type="application/json" length="1"/>' .
            '</item></channel></rss>',
            200,
            'application/rss+xml; charset=utf-8'
        );
    }

    lab_text_response('Callback listener ready.', 200);
}

function lab_handle_app(string $path, string $method): never
{
    // 16 个真实业务接口：路径、级别和参数都来自 business_scenarios.php。
    if (lab_business_route($path) !== null) {
        lab_business_dispatch($path, $method);
    }

    // 浏览器只拿到运行关卡所需的最小信息：标题、提示、表单字段和业务路由。
    // FLAG、目标地址、业务描述和源码都不在初始响应中；源码只在通关响应里下发。
    if ($path === '/api/bootstrap' && $method === 'GET') {
        $challenges = lab_challenges();
        $publicChallenges = [];

        foreach ($challenges as $id => $challenge) {
            $business = is_array($challenge['business'] ?? null) ? $challenge['business'] : [];
            $publicChallenges[] = [
                'id' => (int) $challenge['id'],
                'title' => (string) $challenge['title'],
                'hints' => array_values($challenge['hints'] ?? []),
                'extraFields' => array_values($challenge['extraFields'] ?? []),
                'business' => array_intersect_key(
                    $business,
                    array_flip(['api', 'param', 'method', 'header', 'headerField', 'solveMode'])
                ),
            ];
        }

        lab_json_response([
            'lab' => [
                'name' => 'SSRF Field Lab',
                'version' => '3.0.0',
            ],
            'challenges' => $publicChallenges,
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

