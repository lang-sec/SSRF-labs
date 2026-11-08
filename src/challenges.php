<?php

declare(strict_types=1);

require_once __DIR__ . '/advanced_challenges.php';
require_once __DIR__ . '/business_scenarios.php';

function lab_file_uri(string $path): string
{
    $normalized = str_replace('\\', '/', $path);

    if (preg_match('/^[A-Za-z]:\//', $normalized) === 1) {
        return 'file:///' . $normalized;
    }

    return 'file://' . $normalized;
}

function lab_level_code_examples(): array
{
    return [
        1 => [
            'label' => 'ProductImageController.php / ImageProxy.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解“服务端请求”为什么比浏览器请求更危险。
 * $input 是业务接口已经解析好的 JSON 请求体。
 */
// POST /products/import-image
// 业务场景：商品图片远程导入
$url = trim((string) ($input['url'] ?? ''));

// 创建 curl 句柄。后续所有请求选项都绑定到这个句柄。
$ch = curl_init($url);
curl_setopt_array($ch, [
    // 让 curl 把响应正文作为字符串返回。
    CURLOPT_RETURNTRANSFER => true,
    // 限制最长等待时间，避免请求一直挂着。
    CURLOPT_TIMEOUT        => 4,
    // 禁用系统代理，确保实验只连接本机目标。
    CURLOPT_PROXY          => '',
]);

// 真正发起请求。这里的网络身份属于 PHP 服务进程，而不是浏览器。
$body   = curl_exec($ch);
// 读取 HTTP 状态码，便于前端展示。
$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
curl_close($ch);

// 没有校验 Host、端口、协议或 IP，直接把完整响应返回。
return [
    'status' => $status,
    'body'   => $body,
];

// 被访问的目标服务：模拟云元数据服务。
if ($path === '/latest/meta-data/iam/security-credentials/lab-role') {
    echo json_encode([
        'AccessKeyId' => 'ASIA_LAB_ONLY_DEMO',
        'Token'       => 'FLAG{...}',
    ], JSON_UNESCAPED_UNICODE);
}
PHP,
        ],
        2 => [
            'label' => 'BrandLogoController.php / LegacyAddressGuard.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解“字符串黑名单”为什么不等于“网络目标校验”。
 * 同一个 127.0.0.1 可以有多种 IP 写法。
 */
// POST /merchants/import-logo
// 业务场景：品牌 Logo 自动抓取
$url = trim((string) ($input['url'] ?? ''));

// 只检查原始 URL 中是否出现几个固定字符串。
// 它不会知道 curl 最终会解析到哪个 IP。
if (preg_match('/(localhost|127\.0\.0\.1)/i', $url)) {
    throw new RuntimeException('目标地址不允许');
}

// parse_url 把 URL 拆成 scheme、host、port、path 等组件。
$parts = parse_url($url);
$host  = (string) ($parts['host'] ?? '');

// 请求前把数字、十六进制等写法转换成标准 IPv4。
// 这一步是功能归一化，不应被误认为安全检查。
$normalizedHost = lab_normalize_host($host);
$fetchUrl = lab_url_with_host($url, $normalizedHost);

// 实际请求仍然访问归一化后的回环地址。
$body = lab_http_get($fetchUrl);

// 学习用的简化归一化函数。
function lab_normalize_host(string $host): string
{
    if (preg_match('/^\d+$/', $host)) {
        return long2ip((int) $host); // 2130706433
    }

    if (preg_match('/^0x([0-9a-f]+)$/i', $host, $match)) {
        return long2ip(hexdec($match[1])); // 0x7f000001
    }

    return $host;
}

// 目标：内部管理服务
// GET http://127.0.0.1:8081/admin
PHP,
        ],
        3 => [
            'label' => 'CampaignAssetController.php / InternalDebug.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解“URL 字符串中包含域名”和“请求 Host 是域名”完全不同。
 */
// POST /campaigns/check-asset
// 业务场景：营销落地页素材检查
$url = trim((string) ($input['url'] ?? ''));

// str_contains 检查整段字符串，路径和查询参数也会被扫描。
if (!str_contains($url, 'shop.local')) {
    throw new RuntimeException('仅允许商店域名');
}

// 真正决定连接目标的是 parse_url 返回的 host。
$parts = parse_url($url);
$host  = (string) ($parts['host'] ?? '');

// host 可以是 127.0.0.1，只要 URL 的其他位置出现 shop.local 就能通过。
$body  = lab_http_get($url);

return [
    'checkedFor' => 'shop.local',
    'actualHost' => $host,
    'body'       => $body,
];

// 目标：内部调试接口
if ($path === '/internal/debug') {
    echo json_encode([
        'requested_source' => $_GET['source'] ?? null,
        'flag'             => 'FLAG{...}',
    ]);
}
PHP,
        ],
        4 => [
            'label' => 'LinkPreviewController.php / PublicRedirect.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解“首跳校验”和“最终连接目标”不是一回事。
 * curl 跟随 302 时会在业务校验之外继续发起请求。
 */
// POST /messages/link-preview
// 业务场景：站外链接预览
$url   = trim((string) ($input['url'] ?? ''));
$parts = parse_url($url);

// 只检查最初的 URL 是否属于公开预览服务。
$host = (string) ($parts['host'] ?? '');
$port = (int) ($parts['port'] ?? 0);

if ($host !== '127.0.0.1' || $port !== 8083) {
    throw new RuntimeException('仅允许公开站点');
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    // 危险点：客户端会自动请求 Location 中的新地址。
    CURLOPT_FOLLOWLOCATION => true, // 没有复查 Location
    CURLOPT_MAXREDIRS      => 3,
    // 即使限制协议，也没有限制跳转后的 Host 和 IP。
    CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
]);
$body = curl_exec($ch);

// 公开重定向服务：读取 to 参数并返回 Location。
// GET /redirect?to=http://127.0.0.1:8081/admin
$target = (string) ($_GET['to'] ?? '');
header('Location: ' . $target, true, 302);
exit;
PHP,
        ],
        5 => [
            'label' => 'AvatarPreviewController.php / RebindDns.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解 DNS 校验和实际连接之间的 TOCTOU 时间差。
 * 第一次解析用于“检查”，第二次解析用于“连接”。
 */
// 业务场景：用户提交 CDN 头像地址，服务端生成远程预览
final class AvatarPreviewController
{
    public function store(
        Request $request,
        DnsLookup $dns,
        RemoteAssetFetcher $fetcher
    ): JsonResponse {
        $url = (string) $request->input('url');
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));

        if (!str_ends_with($host, '.cdn-preview.ssrf.lab')) {
            return response()->json(['error' => 'Unsupported avatar CDN'], 422);
        }

        // 业务安全检查只解析了一次。攻击者把 DNS TTL 设为 0，
        // 第一次返回 203.0.113.77，让这里认为目标是公网。
        $validationIp = $dns->lookup($host);
        if (filter_var(
            $validationIp,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false) {
            return response()->json(['error' => 'Internal target'], 403);
        }

        // HTTP 客户端建立连接时会再次查询 DNS。
        // 教学 DNS 在第二次查询时返回 127.0.0.1。
        $body = $fetcher->get($url, [
            'timeout' => 3,
            'follow_redirects' => false,
        ]);

        return response()->json([
            'validated_ip' => $validationIp,
            'preview' => $body,
        ]);
    }
}

// 教学模拟：RebindDns 的第二次解析结果
// avatar-7f3a.cdn-preview.ssrf.lab => 127.0.0.1
PHP,
        ],
        6 => [
            'label' => 'AttachmentPreviewController.php / FileScheme.php',
            'code' => <<<'PHP'
<?php
/*
 * 学习目标：理解协议会改变请求的下游 Sink。
 * http:// 进入网络客户端，file:// 进入文件系统读取。
 */
// POST /knowledge-base/preview-attachment
// 业务场景：知识库附件预览
$url = trim((string) ($input['url'] ?? ''));

// 危险协议黑名单只列出三项，没有禁止 file。
if (preg_match('/^(gopher|dict|ftp):/i', $url)) {
    throw new RuntimeException('危险协议');
}

// 从 URL 中读取协议名，例如 http、file、gopher。
$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
if ($scheme === 'file') {
    // 把 file:///C:/... 转成本机文件路径。
    $path = lab_file_url_to_path($url);
    $expected = realpath(__DIR__ . '/../secrets/level6.txt');

    // 实验安全边界：真实漏洞通常没有这一层限制。
    if ($path === null || $path !== $expected) {
        throw new RuntimeException('实验边界已拦截');
    }

    // file_get_contents 读取本地文件，并继承 PHP 进程权限。
    $body = file_get_contents($path);
}

return [
    'scheme' => $scheme,
    'body'   => $body ?? '',
];

// 如果没有实验边界，file_get_contents 可以读取
// 当前 PHP 进程有权访问的任意本地文件。
PHP,
        ],
    ];
}

function lab_vulnerability_causes(): array
{
    return [
        1 => [
            'summary' => '核心错误是把 URL 当成普通业务参数，而 URL 实际上决定了服务器从哪里、用什么网络身份发起连接。',
            'points' => [
                [
                    'title' => '不可信输入直接决定请求目标',
                    'body' => '请求体中的 url 没有经过协议、Host、端口或最终 IP 校验，就直接传给 curl_init。调用者不只控制了响应内容，还控制了请求目的地。',
                ],
                [
                    'title' => '服务端网络身份被借用',
                    'body' => '浏览器无法访问 127.0.0.1:8081 或 8082，但业务服务运行在本机，能够以服务端身份访问这些内部端口。SSRF 的信任问题正发生在浏览器边界之外。',
                ],
                [
                    'title' => '缺少完整的目标约束',
                    'body' => '代码没有限制协议、域名、IP、端口，也没有区分公网目标和回环、私网、链路本地地址。只要目标可达，服务端就会发起请求。',
                ],
                [
                    'title' => '响应被完整回显',
                    'body' => '请求结果直接返回给调用者，把原本可能只能探测连通性的 SSRF 变成了可读取内部响应的完整 SSRF。',
                ],
            ],
            'keyGap' => '没有把用户输入约束到业务真正允许访问的目标集合，也没有为服务端请求建立独立的安全边界。',
        ],
        2 => [
            'summary' => '过滤器判断的是原始 URL 字符串，而网络栈最终连接的是归一化后的 IP，两者不是同一个安全对象。',
            'points' => [
                [
                    'title' => '黑名单只覆盖少量字符串',
                    'body' => '规则只屏蔽 localhost 和 127.0.0.1，但同一个回环地址还可以写成 127.0.0.2、2130706433、0x7f000001 等形式。',
                ],
                [
                    'title' => '校验对象与实际连接对象不一致',
                    'body' => '正则检查的是用户输入的文本，curl 和 DNS 在请求阶段才把主机名转换成 IP。攻击者利用两个阶段之间的表示差异绕过检查。',
                ],
                [
                    'title' => '没有检查最终解析 IP',
                    'body' => '即使 URL 中不包含敏感字符串，只要最终连接的 IP 落在回环、私网或保留网段，也应该被拒绝。当前实现没有做这一层判断。',
                ],
                [
                    'title' => '黑名单天然不完整',
                    'body' => '地址编码、IPv6、十进制、十六进制、特殊域名和重定向都可以扩展绕过面。只要策略是“禁止已知坏字符串”，就难以覆盖所有等价写法。',
                ],
            ],
            'keyGap' => '安全判断停留在字符串层，没有落到 URL 解析结果和最终网络连接 IP 上。',
        ],
        3 => [
            'summary' => '应用把“完整 URL 中出现 shop.local”错误地等同于“请求 Host 是 shop.local”，导致域名检查位置与真实请求目标分离。',
            'points' => [
                [
                    'title' => '检查了整段 URL，而不是 Host',
                    'body' => 'str_contains 会在协议、路径、查询参数和片段中查找 shop.local，但真正决定访问哪台服务器的是 parse_url 得到的 host。',
                ],
                [
                    'title' => '查询参数不影响连接目标',
                    'body' => '目标地址写成 127.0.0.1:8081/internal/debug?source=shop.local 时，shop.local 只是一个参数值，实际连接的仍然是内部调试接口。',
                ],
                [
                    'title' => '字符串匹配无法表达域名边界',
                    'body' => '包含 shop.local 不代表 Host 等于 shop.local。即使改成 contains 检查域名，也可能被 userinfo、子域名或编码形式干扰。',
                ],
                [
                    'title' => '白名单缺少精确语义',
                    'body' => '白名单应该限制准确的 Host、端口和协议，而不是允许任意 URL 只要携带一个受信任关键词就通过。',
                ],
            ],
            'keyGap' => '安全策略基于关键词出现位置，而不是基于解析后的 Host、端口和最终连接目标。',
        ],
        4 => [
            'summary' => '校验和实际请求之间存在状态变化：首跳 URL 合法，但服务端跟随重定向后访问了另一个内网目标。',
            'points' => [
                [
                    'title' => '只校验第一次请求',
                    'body' => '代码只检查初始 URL 是否指向公开重定向服务，却没有检查服务端最终会跟随到哪个 Location。',
                ],
                [
                    'title' => 'HTTP 客户端自动跟随跳转',
                    'body' => 'CURLOPT_FOLLOWLOCATION 为 true 时，curl 会自动请求重定向目标。攻击者只需要控制第一跳，就能把后续请求引向内网。',
                ],
                [
                    'title' => '重定向路径没有重新鉴权',
                    'body' => '第一跳通过校验不等于第二跳可信。每次重定向都应该重新解析 Host、端口和 IP，并重新应用同一套安全策略。',
                ],
                [
                    'title' => '业务场景放大了风险',
                    'body' => '公开站点的开放重定向、登录跳转或 URL 中转接口都可能成为跳板，最终让服务端访问内部管理接口。',
                ],
            ],
            'keyGap' => '安全边界没有贯穿完整请求生命周期，只保护了首跳，遗漏了自动重定向产生的后续连接。',
        ],
        5 => [
            'summary' => '漏洞来自两次 DNS 解析之间的时间差：安全校验看到公网 IP，HTTP 连接看到回环 IP，而业务没有把两次结果绑定起来。',
            'points' => [
                [
                    'title' => '校验解析和连接解析相互独立',
                    'body' => '头像预览业务先调用 dns.lookup 做安全检查，之后 HTTP 客户端建立连接时再次解析域名。两次查询可能返回不同结果。',
                ],
                [
                    'title' => '攻击者可以控制 DNS 答复',
                    'body' => '攻击者把域名 TTL 设置为 0，并让权威 DNS 第一次返回 203.0.113.77 之类的公网地址，第二次返回 127.0.0.1。',
                ],
                [
                    'title' => '检查结果没有固定到连接',
                    'body' => '安全校验只保存了 IP 判断结果，没有把该 IP 固定给实际 socket 连接。curl 仍然根据域名重新解析，因此绕过发生在连接阶段。',
                ],
                [
                    'title' => '业务域名允许通配更扩大攻击面',
                    'body' => '头像预览业务接受 cdn-preview.ssrf.lab 的子域名，攻击者可以使用任意短 TTL 子域名承载重绑定记录，直到连接命中内部服务。',
                ],
            ],
            'keyGap' => 'DNS 校验结果没有与真实连接绑定，存在“先检查、后解析”的经典时间差。',
        ],
        6 => [
            'summary' => '安全策略使用了危险协议黑名单，而不是协议白名单；请求进入不同协议处理器后，危险操作从网络访问变成了本地文件读取。',
            'points' => [
                [
                    'title' => '黑名单遗漏未知协议',
                    'body' => '代码只禁止 gopher、dict 和 ftp，却没有禁止 file。安全策略默认允许任何没有列出的协议，导致 file:// 进入危险分支。',
                ],
                [
                    'title' => '协议决定了下游 Sink 的能力',
                    'body' => '同一个 URL 参数经过 http:// 会触发网络请求，经过 file:// 会触发文件系统读取。攻击目标从内网服务扩展到了服务器本地文件。',
                ],
                [
                    'title' => 'file_get_contents 继承了进程权限',
                    'body' => '本地文件读取能力取决于 PHP 进程权限。若没有目录和文件白名单，进程有权读取的配置、密钥和源码都可能暴露。',
                ],
                [
                    'title' => '缺少协议和目录双重约束',
                    'body' => '本靶场为了安全只允许读取 secrets/level6.txt，但真实漏洞通常还会缺少目录限制、协议白名单和 HTTP 客户端能力收敛。',
                ],
            ],
            'keyGap' => '用不完整的协议黑名单作为信任边界，没有默认拒绝其他协议，也没有约束文件系统访问范围。',
        ],
    ];
}

function lab_challenges(): array
{
    $root = dirname(__DIR__);
    $secretPath = $root . DIRECTORY_SEPARATOR . 'secrets' . DIRECTORY_SEPARATOR . 'level6.txt';
    $codeExamples = lab_level_code_examples();
    $causes = lab_vulnerability_causes();

    $challenges = [
        1 => [
            'id' => 1,
            'key' => 'direct',
            'title' => '直连内部服务',
            'difficulty' => '基础',
            'summary' => '商品后台允许商家提交远程图片 URL，图片代理直接下载并返回预览。',
            'concept' => '图片导入只应该是“读取一张商品图”，但代码把完整网络目标交给了用户，业务服务器因此会带着自己的内网身份访问任意地址。',
            'goal' => '让商品图片导入服务读取模拟元数据凭据。',
            'targetLabel' => '商品图片代理 :8082',
            'target' => 'http://127.0.0.1:8082/latest/meta-data/iam/security-credentials/lab-role',
            'codeLabel' => $codeExamples[1]['label'],
            'snippet' => $codeExamples[1]['code'],
            'cause' => $causes[1],
            'filter' => '无校验：只要目标可达，服务端就会发起请求。',
            'hints' => [
                '浏览器访问不到内部服务，不代表业务服务器访问不到。',
                '把请求交给服务端，而不是让浏览器直接打开链接。',
                '提交：http://127.0.0.1:8082/latest/meta-data/iam/security-credentials/lab-role',
            ],
            'answerSteps' => [
                '确认输入框中的 URL 由服务端执行请求。',
                '直接提交模拟元数据地址 /latest/meta-data/iam/security-credentials/lab-role。',
                '响应中的 FLAG 被返回，说明业务服务器成功访问了内部链路。',
            ],
            'defense' => '渲染远程内容前先建立目标白名单；禁止访问回环、私网、链路本地地址和云元数据地址。',
            'successFlag' => 'FLAG{SSRF_DIRECT_METADATA_ACCESS}',
        ],
        2 => [
            'id' => 2,
            'key' => 'blacklist',
            'title' => '黑名单变形',
            'difficulty' => '入门',
            'summary' => '品牌 Logo 导入只屏蔽了几个常见回环字符串，仍然会下载任意远程资源。',
            'concept' => '商家 Logo 地址被直接交给图片客户端。同一台回环主机可以写成多种格式，字符串黑名单无法覆盖最终网络目标。',
            'goal' => '绕过品牌 Logo 地址黑名单并读取内部管理标记。',
            'targetLabel' => '品牌 Logo 抓取 :8081',
            'target' => 'http://127.0.0.1:8081/admin',
            'codeLabel' => $codeExamples[2]['label'],
            'snippet' => $codeExamples[2]['code'],
            'cause' => $causes[2],
            'filter' => '黑名单：localhost、127.0.0.1。',
            'hints' => [
                '过滤器比较的是字符串，不是最终连接到的 IP。',
                '127.0.0.1 的整数形式是 2130706433，也可以写成十六进制 0x7f000001。',
                '提交：http://2130706433:8081/admin',
            ],
            'answerSteps' => [
                '直接提交 127.0.0.1 会被字符串黑名单拦截。',
                '把 127.0.0.1 转为十进制整数 2130706433，或十六进制 0x7f000001。',
                '服务端归一化地址后仍访问同一回环服务，返回内部 /admin 内容。',
            ],
            'defense' => '不要对输入字符串做黑名单判断。解析 URL 后解析全部 DNS 结果，对最终 IP 做私网/保留地址检查。',
            'successFlag' => 'FLAG{SSRF_BLACKLIST_IP_ENCODING}',
        ],
        3 => [
            'id' => 3,
            'key' => 'keyword',
            'title' => '关键词白名单',
            'difficulty' => '入门',
            'summary' => '营销素材检查只要看到 shop.local，就会允许素材服务抓取完整 URL。',
            'concept' => '运营素材 URL 中的关键词可以出现在查询参数里，而真正决定访问目标的 Host 仍然是内部地址。',
            'goal' => '让营销素材检查通过 shop.local 关键词校验，同时访问内部调试接口。',
            'targetLabel' => '营销素材检查 :8081',
            'target' => 'http://127.0.0.1:8081/internal/debug?source=shop.local',
            'codeLabel' => $codeExamples[3]['label'],
            'snippet' => $codeExamples[3]['code'],
            'cause' => $causes[3],
            'filter' => '白名单：完整 URL 必须包含 shop.local。',
            'hints' => [
                '解析器真正使用的是 host，而检查器可能在看整段字符串。',
                '把 shop.local 放进查询参数，不会改变请求目标。',
                '提交：http://127.0.0.1:8081/internal/debug?source=shop.local',
            ],
            'answerSteps' => [
                '构造一个访问内部服务的 URL。',
                '在查询参数中加入 shop.local，使字符串检查通过。',
                'Host 仍然是 127.0.0.1，服务端最终请求内部调试接口。',
            ],
            'defense' => '先解析 host，再对 host 做精确匹配；不要对整段 URL 使用 contains、正则或 startsWith 作为白名单。',
            'successFlag' => 'FLAG{SSRF_KEYWORD_FILTER_BYPASS}',
        ],
        4 => [
            'id' => 4,
            'key' => 'redirect',
            'title' => '重定向绕过',
            'difficulty' => '进阶',
            'summary' => '站外链接预览只检查公开首跳，随后自动跟随重定向进入内网。',
            'concept' => '聊天中的预览链接首跳可以合法，但预览客户端跟随 302 后，最终页面可能位于内部管理服务。',
            'goal' => '利用公开链接的中转跳转，让预览服务读取内部管理页面。',
            'targetLabel' => '聊天链接预览 :8083',
            'target' => '/redirect?to=内部管理服务',
            'codeLabel' => $codeExamples[4]['label'],
            'snippet' => $codeExamples[4]['code'],
            'cause' => $causes[4],
            'filter' => '首跳限制：只能从 127.0.0.1:8083 开始。',
            'hints' => [
                '先找到公开站点上的 /redirect?to= 端点。',
                'URL 编码后，把内部管理服务地址放进 to 参数。',
                '提交：http://127.0.0.1:8083/redirect?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin',
            ],
            'answerSteps' => [
                '第一跳使用允许的公开站点 127.0.0.1:8083。',
                '利用 /redirect?to= 返回 302，把目标指向 127.0.0.1:8081/admin。',
                '客户端跟随跳转且没有复查新目标，于是读取内部管理页面。',
            ],
            'defense' => '每跟随一次重定向都重新解析并校验目标；更稳妥的做法是禁用自动跳转，手动处理且限制跳转次数。',
            'successFlag' => 'FLAG{SSRF_REDIRECT_CHAIN}',
        ],
        5 => [
            'id' => 5,
            'key' => 'rebind',
            'title' => 'DNS 重绑定',
            'difficulty' => '进阶',
            'summary' => '头像预览服务校验域名一次，HTTP 客户端连接时又重新解析一次。',
            'concept' => '攻击者控制短 TTL DNS，让安全校验得到公网 IP，真正连接时得到回环 IP；两次解析之间存在可利用的时间差。',
            'goal' => '让头像预览服务读取模拟元数据服务中的 lab-role 凭据。',
            'targetLabel' => 'avatar-7f3a.cdn-preview.ssrf.lab:8082',
            'target' => 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data/iam/security-credentials/lab-role',
            'codeLabel' => $codeExamples[5]['label'],
            'snippet' => $codeExamples[5]['code'],
            'cause' => $causes[5],
            'filter' => '头像预览业务：首次解析为 203.0.113.77 时放行；HTTP 客户端连接时再次解析为 127.0.0.1。',
            'hints' => [
                '头像预览服务会先检查 CDN 域名的解析结果，再交给 HTTP 客户端下载资源。',
                '攻击者把 DNS TTL 设为 0：第一次返回 203.0.113.77，第二次返回 127.0.0.1。',
                '提交：http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data/iam/security-credentials/lab-role',
            ],
            'answerSteps' => [
                '提交 avatar-7f3a.cdn-preview.ssrf.lab 下的头像资源 URL。',
                '业务安全校验第一次解析得到 203.0.113.77，判断为公网并放行。',
                'HTTP 客户端连接时第二次解析得到 127.0.0.1，最终读取 8082 端口上的模拟元数据。',
            ],
            'defense' => '校验通过后应把 IP 固定给实际连接，不能再次解析；同时限制目标域名、端口、重定向和网络出口。',
            'successFlag' => 'FLAG{SSRF_DNS_REBINDING}',
        ],
        6 => [
            'id' => 6,
            'key' => 'protocol',
            'title' => '协议走私',
            'difficulty' => '高阶',
            'summary' => '知识库附件预览只禁止部分危险协议，却遗漏了本地文件协议。',
            'concept' => '附件预览原本用于读取远程文档，但同一个 URL 参数切到 file:// 后会进入文件系统读取分支。',
            'goal' => '利用附件预览功能读取本靶场指定的教学文件。',
            'targetLabel' => '附件预览文件',
            'target' => lab_file_uri($secretPath),
            'codeLabel' => $codeExamples[6]['label'],
            'snippet' => $codeExamples[6]['code'],
            'cause' => $causes[6],
            'filter' => '协议黑名单：gopher、dict、ftp。',
            'hints' => [
                '黑名单列出的协议不是完整集合。',
                'PHP 的 file_get_contents 支持 file://，它可以读取本地文件。',
                '提交：' . lab_file_uri($secretPath),
            ],
            'answerSteps' => [
                '观察过滤器只拦截 gopher、dict、ftp。',
                '使用未列出的 file:// 协议指向教学密钥文件。',
                '实验边界只允许读取 secrets/level6.txt，响应中返回 FLAG。',
            ],
            'defense' => '默认使用协议白名单（通常只允许 https），关闭客户端的 file、gopher、dict 等能力，并限制读取目录。',
            'successFlag' => 'FLAG{SSRF_PROTOCOL_FILE_SMUGGLING}',
        ],
    ];

    $allChallenges = array_replace($challenges, lab_advanced_challenges());
    $businessScenarios = lab_business_scenarios();

    foreach ($allChallenges as $id => &$challenge) {
        $challenge['business'] = $businessScenarios[$id] ?? null;
    }
    unset($challenge);

    return $allChallenges;
}

function lab_defense_guide(): array
{
    return [
        [
            'title' => '解析后再判断',
            'body' => '用可靠的 URL 解析器提取 scheme、host、port，禁止基于原始字符串 contains 或正则做安全决策。',
        ],
        [
            'title' => '校验最终 IP',
            'body' => '解析域名的所有 A/AAAA 记录，拒绝 127.0.0.0/8、10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、169.254.0.0/16、::1 和 ULA 地址。',
        ],
        [
            'title' => '固定连接目标',
            'body' => '把校验通过的 IP 固定到实际连接，避免校验与连接之间再次解析，防止 DNS 重绑定。',
        ],
        [
            'title' => '监控每一次跳转',
            'body' => '禁用自动重定向，或对每个 Location 重新解析与校验；限制跳转次数和目标域名。',
        ],
        [
            'title' => '协议与端口白名单',
            'body' => '只启用业务确实需要的 https 协议和目标端口，不要依赖危险协议黑名单。',
        ],
        [
            'title' => '网络层兜底',
            'body' => '让抓取服务运行在独立网段，通过出站代理和网络策略只允许访问批准的目标；应用校验不能是唯一防线。',
        ],
        [
            'title' => '把二级 URL 当成新输入',
            'body' => 'Header、HTML 子资源、RSS enclosure 和远程 JSON 中的 URL 都要重新执行解析、DNS 与目标策略。',
        ],
        [
            'title' => '为盲 SSRF 建立观测',
            'body' => '记录完整出站目标，监控异常 DNS 和回调域名；即使目标响应不回显，也要能发现请求是否发生。',
        ],
    ];
}

