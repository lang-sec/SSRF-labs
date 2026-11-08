<?php

declare(strict_types=1);

/**
 * 16 个真实业务接口。
 *
 * 每个 handler 都包含该业务自己的（故意有缺陷的）校验和请求逻辑；
 * 出网统一走 src/egress.php 的实验网关，网关只负责安全边界和传输。
 */

function lab_business_routes(): array
{
    static $routes = null;
    if ($routes !== null) {
        return $routes;
    }

    $routes = [];
    foreach (lab_business_scenarios() as $level => $scenario) {
        $path = (string) ($scenario['api'] ?? '');
        if ($path === '') {
            continue;
        }

        $routes[$path] = [
            'path' => $path,
            'level' => (int) $level,
            'method' => strtoupper((string) ($scenario['method'] ?? 'POST')),
            'param' => (string) ($scenario['param'] ?? 'url'),
            'handler' => 'lab_business_level_' . (int) $level,
        ];
    }

    return $routes;
}

function lab_business_route(string $path): ?array
{
    return lab_business_routes()[$path] ?? null;
}

function lab_business_input(): array
{
    static $input = null;
    if ($input !== null) {
        return $input;
    }

    // 同时支持 JSON body、表单编码和查询参数；JSON 优先。
    $input = array_merge($_GET, $_POST, lab_read_json_body());

    return $input;
}

function lab_business_param(array $route): string
{
    $param = (string) $route['param'];
    $value = trim((string) (lab_business_input()[$param] ?? ''));

    if ($value === '') {
        lab_json_response([
            'error' => 'Missing required parameter: ' . $param,
            'param' => $param,
        ], 422);
    }

    if (strlen($value) > 2048) {
        lab_json_response(['error' => 'URL 长度不能超过 2048 字符'], 422);
    }

    return $value;
}

function lab_business_blocked(int $started, string $message, string $target): array
{
    $result = lab_result_error($message, $started, 'blocked');
    $result['transport']['target'] = $target;

    return $result;
}

function lab_business_envelope(array $challenge, array $fetch, string $allowedMessage, ?bool $solved = null): array
{
    $blocked = (bool) ($fetch['blocked'] ?? false);
    $ok = !$blocked && (bool) ($fetch['ok'] ?? false);
    $body = (string) ($fetch['body'] ?? '');

    $message = match (true) {
        $blocked => (string) ($fetch['reason'] ?? '实验边界拦截。'),
        $ok => $allowedMessage,
        default => (string) (($fetch['error'] ?? '') !== '' ? $fetch['error'] : '请求失败。'),
    };

    return [
        'ok' => $ok,
        'blocked' => $blocked,
        'validation' => [
            'decision' => $blocked ? 'blocked' : ($ok ? 'allowed' : 'error'),
            'message' => $message,
        ],
        'transport' => [
            'method' => (string) ($fetch['method'] ?? 'GET'),
            'target' => (string) ($fetch['target'] ?? ''),
            'finalUrl' => (string) ($fetch['finalUrl'] ?? ''),
            'resolvedIp' => $fetch['resolvedIp'] ?? null,
        ],
        'response' => [
            'status' => (int) ($fetch['status'] ?? 0),
            'durationMs' => (int) ($fetch['durationMs'] ?? 0),
            'bytes' => strlen($body),
            'body' => $body,
        ],
        'solved' => $solved ?? str_contains($body, (string) ($challenge['successFlag'] ?? '')),
    ];
}

function lab_business_finish(int $level, array $challenge, string $logUrl, array $result, int $started): never
{
    lab_append_log([
        'level' => $level,
        'levelTitle' => (string) ($challenge['title'] ?? ''),
        'url' => $logUrl,
        'decision' => (string) ($result['validation']['decision'] ?? 'error'),
        'message' => (string) ($result['validation']['message'] ?? ''),
        'status' => (int) ($result['response']['status'] ?? 0),
        'durationMs' => (int) ($result['response']['durationMs'] ?? 0),
        'finalUrl' => (string) ($result['transport']['finalUrl'] ?? ''),
        'solved' => (bool) ($result['solved'] ?? false),
    ]);

    $payload = [
        'level' => $level,
        'result' => $result,
        'elapsedMs' => (int) round((hrtime(true) - $started) / 1_000_000),
    ];

    // 源码只随"已通关"的响应下发，初始 bootstrap 中不包含源码。
    if (($result['solved'] ?? false) === true) {
        $payload['source'] = [
            'codeLabel' => (string) ($challenge['codeLabel'] ?? ''),
            'snippet' => (string) ($challenge['snippet'] ?? ''),
        ];
    }

    lab_json_response($payload);
}

function lab_business_dispatch(string $path, string $method): never
{
    $route = lab_business_route($path);
    if ($route === null) {
        lab_json_response(['error' => 'Business endpoint not found'], 404);
    }

    if (strtoupper($method) !== $route['method']) {
        header('Allow: ' . $route['method']);
        lab_json_response(['error' => 'Method not allowed'], 405);
    }

    $challenges = lab_challenges();
    $level = (int) $route['level'];
    if (!isset($challenges[$level])) {
        lab_json_response(['error' => 'Unknown business route'], 404);
    }

    $handler = (string) $route['handler'];
    if (!function_exists($handler)) {
        lab_json_response(['error' => 'Business handler unavailable'], 500);
    }

    $handler($route, $challenges[$level], hrtime(true));
}

/* -------------------------------------------------------------------------
 * 第 1 关：商品图片远程导入
 * 图片代理把用户给的 URL 直接交给 HTTP 客户端，没有任何目标校验。
 * ---------------------------------------------------------------------- */
function lab_business_level_1(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $fetch = lab_egress_http(1, $url);

    $body = (string) ($fetch['body'] ?? '');
    $hasMd5 = (bool) ($fetch['ok'] ?? false) && preg_match('/\b[a-f0-9]{32}\b/i', $body, $match) === 1;
    $message = $hasMd5
        ? '目标根路径返回了 MD5，存在有回显 SSRF。'
        : '目标根路径没有返回 MD5。';

    $result = lab_business_envelope($challenge, $fetch, $message, $hasMd5);
    lab_business_finish(1, $challenge, $url, $result, $started);
}

/* -------------------------------------------------------------------------
 * 第 2 关：品牌 Logo 自动抓取
 * 只对原始 URL 做字符串黑名单，不做地址归一化，也不检查最终 IP。
 * ---------------------------------------------------------------------- */
function lab_business_level_2(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);

    if (preg_match('/(?:localhost|127\.0\.0\.1)/i', $url) === 1) {
        lab_business_finish(2, $challenge, $url, lab_business_blocked($started, '黑名单命中：URL 中包含 localhost 或 127.0.0.1。', $url), $started);
    }

    $fetch = lab_egress_http(2, $url);
    lab_business_finish(2, $challenge, $url, lab_business_envelope($challenge, $fetch, '黑名单未命中，图片服务开始下载品牌资源。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 3 关：营销落地页素材检查
 * 对完整 URL 做 str_contains；查询参数里的 shop.local 也会让检查通过。
 * ---------------------------------------------------------------------- */
function lab_business_level_3(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);

    if (!str_contains($url, 'shop.local')) {
        lab_business_finish(3, $challenge, $url, lab_business_blocked($started, '白名单未命中：完整 URL 必须包含 shop.local。', $url), $started);
    }

    $fetch = lab_egress_http(3, $url);
    lab_business_finish(3, $challenge, $url, lab_business_envelope($challenge, $fetch, '关键词校验通过，素材服务抓取了远程内容。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 4 关：站外链接预览
 * 只校验第一跳是否属于公开重定向服务，随后自动跟随 Location。
 * ---------------------------------------------------------------------- */
function lab_business_level_4(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $parts = lab_parse_http_url($url);

    if ($parts === null || $parts['host'] !== '127.0.0.1' || $parts['port'] !== LAB_REDIRECT_PORT) {
        lab_business_finish(4, $challenge, $url, lab_business_blocked($started, '首跳限制：URL 必须以 http://127.0.0.1:8083 开始。', $url), $started);
    }

    $fetch = lab_egress_http(4, $url, ['followRedirects' => true]);
    lab_business_finish(4, $challenge, $url, lab_business_envelope($challenge, $fetch, '首跳校验通过，HTTP 客户端自动跟随了重定向。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 5 关：CDN 头像预览（DNS 重绑定）
 * 业务只解析一次用于校验；HTTP 客户端连接时再次解析，得到不同 IP。
 * ---------------------------------------------------------------------- */
function lab_business_level_5(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $parts = lab_parse_http_url($url);

    if ($parts === null || !lab_is_rebind_host($parts['host'])) {
        lab_business_finish(5, $challenge, $url, lab_business_blocked($started, '业务校验未通过：头像预览地址必须使用受测 CDN 域名。', $url), $started);
    }

    $resolver = new LabResolver();
    $validationIp = $resolver->lookupOne($parts['host']);
    if ($validationIp === null || lab_is_private_ip($validationIp)) {
        lab_business_finish(5, $challenge, $url, lab_business_blocked($started, 'DNS 检查：首次解析结果指向内部地址，业务拒绝请求。', $url), $started);
    }

    // TOCTOU：连接阶段再次解析，得到回环地址。
    $connectionIp = $resolver->connectionIp($parts['host']);
    if ($connectionIp === null) {
        lab_business_finish(5, $challenge, $url, lab_result_error('DNS 解析失败，无法建立连接。', $started), $started);
    }

    $fetch = lab_egress_http(5, $url, ['resolveIp' => $connectionIp]);
    lab_business_finish(5, $challenge, $url, lab_business_envelope($challenge, $fetch, '头像预览业务首次解析返回 203.0.113.77，安全校验通过。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 6 关：知识库附件预览
 * 危险协议黑名单只列出 gopher/dict/ftp，file 协议漏过。
 * ---------------------------------------------------------------------- */
function lab_business_level_6(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

    if (in_array($scheme, ['gopher', 'dict', 'ftp'], true)) {
        lab_business_finish(6, $challenge, $url, lab_business_blocked($started, '危险协议：gopher、dict、ftp 已被拦截。', $url), $started);
    }

    $fetch = $scheme === 'file' ? lab_egress_read_file(6, $url) : lab_egress_http(6, $url);
    lab_business_finish(6, $challenge, $url, lab_business_envelope($challenge, $fetch, '协议黑名单未拦截该协议，附件预览读取了目标。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 7 关：社交头像同步
 * 校验器读取 parse_url 的 user 组件，HTTP 客户端实际使用 host。
 * ---------------------------------------------------------------------- */
function lab_business_level_7(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $parts = parse_url($url);
    $checkedHost = is_array($parts) ? (string) ($parts['user'] ?? '') : '';

    if ($checkedHost !== 'shop.local') {
        lab_business_finish(7, $challenge, $url, lab_business_blocked($started, '域名白名单未命中：解析后的允许域必须是 shop.local。', $url), $started);
    }

    $fetch = lab_egress_http(7, $url);
    lab_business_finish(7, $challenge, $url, lab_business_envelope($challenge, $fetch, 'userinfo 组件通过校验，远程资源客户端访问了真实 Host。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 8 关：静态资源迁移
 * 黑名单覆盖了少量回环写法，但遗漏八进制、缩写和 IPv4 映射 IPv6。
 * ---------------------------------------------------------------------- */
function lab_business_level_8(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);

    if (preg_match('/(?:localhost|127\.0\.0\.1|2130706433|0x7f000001)/i', $url) === 1) {
        lab_business_finish(8, $challenge, $url, lab_business_blocked($started, '高级黑名单命中：常见回环表示已被拦截。', $url), $started);
    }

    $fetch = lab_egress_http(8, $url);
    lab_business_finish(8, $challenge, $url, lab_business_envelope($challenge, $fetch, '高级黑名单未命中，资源下载器归一化地址后访问了目标。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 9 关：合作伙伴媒体同步
 * 一次 DNS 查询返回多条记录，安全检查只看第一条。
 * ---------------------------------------------------------------------- */
function lab_business_level_9(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $parts = lab_parse_http_url($url);

    if ($parts === null || !lab_is_dual_dns_host($parts['host'])) {
        lab_business_finish(9, $challenge, $url, lab_business_blocked($started, 'DNS 白名单未命中：目标必须属于 dual-cdn.ssrf.lab。', $url), $started);
    }

    $resolver = new LabResolver();
    $records = $resolver->lookup($parts['host']);
    $firstIp = $records[0] ?? null;
    if ($firstIp === null || lab_is_private_ip($firstIp)) {
        lab_business_finish(9, $challenge, $url, lab_business_blocked($started, 'DNS 检查：第一条 A 记录指向内部地址，业务拒绝请求。', $url), $started);
    }

    // 媒体抓取器可能选择同一应答中的另一条记录。
    $connectionIp = $records[1] ?? $firstIp;
    $fetch = lab_egress_http(9, $url, ['resolveIp' => $connectionIp]);
    lab_business_finish(9, $challenge, $url, lab_business_envelope($challenge, $fetch, 'DNS 校验只查看了第一条公网 A 记录，安全校验通过。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 10 关：聊天链接预览
 * 只校验公开重定向链的入口，客户端连续跟随多次跳转。
 * ---------------------------------------------------------------------- */
function lab_business_level_10(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $parts = lab_parse_http_url($url);
    $path = $parts === null ? '' : (string) ($parts['parts']['path'] ?? '');

    if ($parts === null || $parts['host'] !== '127.0.0.1' || $parts['port'] !== LAB_REDIRECT_PORT || $path !== '/redirect/chain') {
        lab_business_finish(10, $challenge, $url, lab_business_blocked($started, '首跳限制：只允许公开的多级重定向入口。', $url), $started);
    }

    $fetch = lab_egress_http(10, $url, ['followRedirects' => true]);
    lab_business_finish(10, $challenge, $url, lab_business_envelope($challenge, $fetch, '首跳重定向地址通过校验，客户端开始自动跟随跳转。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 11 关：Webhook 连通性测试
 * 只校验 base_url，真正的目标来自未校验的 X-Forwarded-Host 请求头。
 * ---------------------------------------------------------------------- */
function lab_business_level_11(array $route, array $challenge, int $started): never
{
    $baseUrl = lab_business_param($route);
    $parts = lab_parse_http_url($baseUrl);
    $path = $parts === null ? '' : (string) ($parts['parts']['path'] ?? '');

    if ($parts === null || $parts['host'] !== '127.0.0.1' || $parts['port'] !== LAB_APP_PORT || $path !== '/webhook/test') {
        lab_business_finish(11, $challenge, $baseUrl, lab_business_blocked($started, 'Webhook 基地址必须是 http://127.0.0.1:8080/webhook/test。', $baseUrl), $started);
    }

    $forwardedHost = trim((string) ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? ''));
    if ($forwardedHost === '') {
        lab_json_response(['error' => 'X-Forwarded-Host header is required'], 422);
    }

    $target = 'http://' . $forwardedHost . '/internal/webhook';
    $fetch = lab_egress_http(11, $target);
    lab_business_finish(11, $challenge, $baseUrl, lab_business_envelope($challenge, $fetch, 'Webhook 基地址通过校验，但 X-Forwarded-Host 被直接拼入内部请求目标。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 12 关：报表导出完成通知（盲 SSRF）
 * 导出服务真实请求用户提供的回调地址，但不回显目标响应。
 * ---------------------------------------------------------------------- */
function lab_business_level_12(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);

    // 读取验证端点的隐藏响应用于判定，但不把目标响应回显给调用方。
    // 目标要先做一次真实 DNS 查询，冷缓存时可能超过 4 秒，因此放宽到 10 秒。
    $fetch = lab_egress_http(12, $url, ['returnBody' => true, 'timeout' => 10]);

    if ((bool) ($fetch['blocked'] ?? false) || !(bool) ($fetch['ok'] ?? false)) {
        lab_business_finish(12, $challenge, $url, lab_business_envelope($challenge, $fetch, ''), $started);
    }

    $target = json_decode((string) ($fetch['body'] ?? ''), true);
    $dnsQueried = is_array($target) && ($target['dns_queried'] ?? false) === true;
    $internalFetch = is_array($target) ? ($target['internal_fetch'] ?? null) : null;

    $solved = $dnsQueried;
    if (is_array($internalFetch) && (int) ($internalFetch['status'] ?? 0) > 0) {
        $fetch['body'] = sprintf(
            '盲请求已发出；目标访问了内部服务 %s，HTTP %d，%d 字节。请到 dnslog 查看 DNS 记录。',
            (string) ($internalFetch['url'] ?? ''),
            (int) ($internalFetch['status'] ?? 0),
            (int) ($internalFetch['bytes'] ?? 0)
        );
    } elseif ($dnsQueried) {
        $fetch['body'] = '盲请求已发出；目标执行了 DNS 查询。请到 dnslog 查看解析记录。';
    } else {
        $fetch['body'] = '请求已发出，但验证端点没有确认 DNS 查询。';
    }

    lab_business_finish(12, $challenge, $url, lab_business_envelope(
        $challenge,
        $fetch,
        '无回显 SSRF 验证完成。',
        $solved
    ), $started);
}

/* -------------------------------------------------------------------------
 * 第 13 关：运营素材采集器
 * 只拦截 file 协议，gopher 仍被 HTTP 客户端允许。
 * ---------------------------------------------------------------------- */
function lab_business_level_13(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

    if ($scheme === 'file') {
        lab_business_finish(13, $challenge, $url, lab_business_blocked($started, 'File protocol blocked', $url), $started);
    }

    $fetch = $scheme === 'gopher' ? lab_egress_gopher(13, $url) : lab_egress_http(13, $url);
    lab_business_finish(13, $challenge, $url, lab_business_envelope($challenge, $fetch, '协议检查只拦截 file，gopher 仍被客户端允许。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 14 关：云存储资源导入
 * 只拦截经典元数据 IP，云厂商内部域名进入白名单后没有解析到最终 IP。
 * ---------------------------------------------------------------------- */
function lab_business_level_14(array $route, array $challenge, int $started): never
{
    $url = lab_business_param($route);

    if (str_contains($url, '169.254.169.254')) {
        lab_business_finish(14, $challenge, $url, lab_business_blocked($started, '云元数据地址黑名单命中：169.254.169.254 已被拦截。', $url), $started);
    }

    $parts = lab_parse_http_url($url);
    if ($parts === null || !lab_is_cloud_metadata_host($parts['host'])) {
        lab_business_finish(14, $challenge, $url, lab_business_blocked($started, '元数据校验：只接受受支持的云厂商内部域名。', $url), $started);
    }

    $resolver = new LabResolver();
    $connectionIp = $resolver->connectionIp($parts['host']);
    if ($connectionIp === null) {
        lab_business_finish(14, $challenge, $url, lab_result_error('云元数据域名解析失败。', $started), $started);
    }

    $fetch = lab_egress_http(14, $url, ['resolveIp' => $connectionIp]);
    lab_business_finish(14, $challenge, $url, lab_business_envelope($challenge, $fetch, '标准元数据 IP 被拦截，但云厂商内部域名未被识别。'), $started);
}

/* -------------------------------------------------------------------------
 * 第 15 关：分享链接卡片生成
 * 页面地址合法，但渲染器会继续加载页面中的 <img> 子资源，且不复验。
 * ---------------------------------------------------------------------- */
function lab_business_level_15(array $route, array $challenge, int $started): never
{
    $pageUrl = lab_business_param($route);
    $page = lab_egress_http(15, $pageUrl);

    if ((bool) ($page['blocked'] ?? false) || !(bool) ($page['ok'] ?? false)) {
        lab_business_finish(15, $challenge, $pageUrl, lab_business_envelope($challenge, $page, ''), $started);
    }

    if (preg_match('/<img\b[^>]*\bsrc=["\']([^"\']+)["\']/i', (string) $page['body'], $match) !== 1) {
        $result = lab_result_error('渲染器页面没有返回可加载的图片资源。', $started);
        $result['transport']['target'] = $pageUrl;
        lab_business_finish(15, $challenge, $pageUrl, $result, $started);
    }

    $resourceUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resource = lab_egress_http(15, $resourceUrl);
    $result = lab_business_envelope($challenge, $resource, '首跳渲染器页面通过校验，但图片渲染器又自动请求了页面内的内网资源。');
    $result['transport']['target'] = $pageUrl;
    if ($result['transport']['finalUrl'] === '') {
        $result['transport']['finalUrl'] = $resourceUrl;
    }

    lab_business_finish(15, $challenge, $pageUrl, $result, $started);
}

/* -------------------------------------------------------------------------
 * 第 16 关：合作伙伴 RSS 导入
 * 订阅地址合法，但导入器直接信任 XML 中的 enclosure 地址。
 * ---------------------------------------------------------------------- */
function lab_business_level_16(array $route, array $challenge, int $started): never
{
    $feedUrl = lab_business_param($route);
    $feed = lab_egress_http(16, $feedUrl);

    if ((bool) ($feed['blocked'] ?? false) || !(bool) ($feed['ok'] ?? false)) {
        lab_business_finish(16, $challenge, $feedUrl, lab_business_envelope($challenge, $feed, ''), $started);
    }

    if (preg_match('/<enclosure\b[^>]*\burl=["\']([^"\']+)["\']/i', (string) $feed['body'], $match) !== 1) {
        $result = lab_result_error('RSS 订阅源没有返回可导入的 enclosure 地址。', $started);
        $result['transport']['target'] = $feedUrl;
        lab_business_finish(16, $challenge, $feedUrl, $result, $started);
    }

    $resourceUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resource = lab_egress_http(16, $resourceUrl);
    $result = lab_business_envelope($challenge, $resource, 'RSS 地址通过校验，但导入器随后自动抓取了订阅内容中的 enclosure 内网地址。');
    $result['transport']['target'] = $feedUrl;
    if ($result['transport']['finalUrl'] === '') {
        $result['transport']['finalUrl'] = $resourceUrl;
    }

    lab_business_finish(16, $challenge, $feedUrl, $result, $started);
}
