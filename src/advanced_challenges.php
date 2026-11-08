<?php

declare(strict_types=1);

function lab_advanced_challenges(): array
{
    return [
        7 => [
            'id' => 7,
            'key' => 'parser',
            'title' => 'URL 解析差异',
            'difficulty' => '进阶',
            'summary' => '业务把 URL 的 userinfo 部分当成了请求 Host。',
            'concept' => '同一段 URL 可以被拆成用户信息、主机、端口和路径。校验器如果取错组件，就会检查 shop.local，而客户端实际连接 127.0.0.1。',
            'goal' => '利用 userinfo 与真实 Host 的差异访问内部解析目标。',
            'targetLabel' => 'shop.local@127.0.0.1:8081',
            'target' => 'http://shop.local@127.0.0.1:8081/internal/parser',
            'codeLabel' => 'RemoteAvatarController.php / UrlComponents.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：认识 URL 的组成，尤其是 userinfo 与 host。
 * 例：http://user@host/path 中，user 是用户信息，host 才是连接目标。
 */
// 业务场景：远程头像只允许来自 shop.local
$url   = (string) $request->input('avatar_url');
// parse_url 会把 URL 拆成多个组件。
$parts = parse_url($url);

// 错误：user 只是 @ 前面的用户信息，不是目标服务器。
$checkedHost = (string) ($parts['user'] ?? '');
if ($checkedHost !== 'shop.local') {
    return response()->json(['error' => 'Untrusted avatar host'], 422);
}

// 实际 HTTP 客户端会使用 host 字段，也就是 @ 后面的地址。
$realHost = (string) ($parts['host'] ?? '');
$client = new RemoteAssetClient();
$body = $client->get($url);

return response()->json([
    'checked_host' => $checkedHost,
    'real_host'    => $realHost,
    'body'         => $body,
]);
PHP,
            'filter' => '错误校验：只检查 URL 的 userinfo 是否为 shop.local。',
            'hints' => [
                'URL 中 @ 前面的内容不一定是 Host。',
                'PHP parse_url 会把 shop.local 放进 user，把 127.0.0.1 放进 host。',
                '提交：http://shop.local@127.0.0.1:8081/internal/parser',
            ],
            'answerSteps' => [
                '把允许域名放到 @ 前面的 userinfo 位置。',
                '@ 后面写真正的内部地址 127.0.0.1:8081。',
                '校验器读到 shop.local，HTTP 客户端实际连接内部服务。',
            ],
            'defense' => '只信任 parse_url 返回的 host，并统一使用同一套 URL 解析结果完成校验和连接；同时校验端口、协议和最终 IP。',
            'cause' => [
                'summary' => '漏洞来自 URL 组件混淆：校验器读取 userinfo，连接器读取 host，两个代码路径对“域名”的理解不一致。',
                'points' => [
                    ['title' => '校验取错 URL 组件', 'body' => '代码使用 $parts["user"] 作为允许域名，而 user 是 @ 前面的用户信息，不决定实际连接目标。'],
                    ['title' => '真实 Host 未参与校验', 'body' => 'parse_url 返回的 host 是 127.0.0.1，但这段值只在请求发出后被记录，没有进入安全判断。'],
                    ['title' => '校验和连接使用了不同字段', 'body' => '安全逻辑看 user，HTTP 客户端看 host。两者同时从同一 URL 解析，却得出了不同的访问目标。'],
                    ['title' => 'userinfo 很容易被误读', 'body' => '带有 @ 的 URL 在日志、正则和临时变量中常被误认为普通域名，导致安全人员高估了过滤效果。'],
                ],
                'keyGap' => '没有让校验和实际连接共享同一个规范化后的 Scheme、Host、Port 和 IP。',
            ],
            'successFlag' => 'FLAG{SSRF_URL_PARSER_CONFUSION}',
        ],
        8 => [
            'id' => 8,
            'key' => 'encoding',
            'title' => '特殊 IP 编码',
            'difficulty' => '进阶',
            'summary' => '静态资源迁移器覆盖了十进制和十六进制，却遗漏了八进制、缩写和 IPv4 映射 IPv6。',
            'concept' => '运维提交的旧资源地址存在多种等价写法。迁移器检查字符串，网络栈却会把它归一化后连接到回环地址。',
            'goal' => '使用非常规回环地址表示让资源迁移器访问内部编码目标。',
            'targetLabel' => '资源迁移 :0177.0.0.1',
            'target' => 'http://0177.0.0.1:8081/internal/encoding',
            'codeLabel' => 'AssetMigrationController.php / LegacyIpNormalizer.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：理解 IP 地址的历史写法。
 * 0177、0x7f、127.1 等形式都可能表示同一个回环地址。
 */
// 业务场景：地址黑名单阻止常见回环写法
$url = (string) $request->input('asset_url');

// 黑名单只匹配四种字符串，但它不是完整的地址规则。
if (preg_match(
    '/(localhost|127\.0\.0\.1|2130706433|0x7f000001)/i',
    $url
)) {
    return response()->json(['error' => 'Blocked address'], 403);
}

$parts = parse_url($url);
$host  = (string) ($parts['host'] ?? '');

// 请求库会把 0177.0.0.1、127.1、IPv4 映射 IPv6
// 统一转换成实际的 127.0.0.1。校验没有做同样的事情。
$normalized = LegacyIpNormalizer::toIpv4($host);
$fetchUrl = Url::replaceHost($url, $normalized);

$body = (new RemoteAssetClient())->get($fetchUrl);
return response()->json(['body' => $body]);
PHP,
            'filter' => '高级黑名单：localhost、127.0.0.1、2130706433、0x7f000001。',
            'hints' => [
                '八进制 0177 等于十进制 127。',
                'IPv4 映射 IPv6 也能表示同一个回环目标。',
                '提交：http://0177.0.0.1:8081/internal/encoding',
            ],
            'answerSteps' => [
                '选择一个不在黑名单中的回环地址表示。',
                '例如 0177.0.0.1 会被归一化为 127.0.0.1。',
                '归一化后的请求仍然访问本机内部服务。',
            ],
            'defense' => '先使用严格解析器把目标转换为标准 IP，再对最终 IP 做回环、私网和保留地址判断。不要维护地址字符串黑名单。',
            'cause' => [
                'summary' => '根因仍是字符串校验与网络语义脱节，只是这次利用了更多 IPv4 和 IPv6 等价表示法。',
                'points' => [
                    ['title' => '黑名单没有覆盖全部等价写法', 'body' => '规则只列举了常见形式，没有覆盖八进制、缩写、混合进制和 IPv4 映射 IPv6。'],
                    ['title' => '解析器接受了历史地址格式', 'body' => '网络库通常兼容 inet_aton 风格地址，0177.0.0.1、127.1 等最终都会连接同一个接口。'],
                    ['title' => '安全判断没有标准化输入', 'body' => '如果先把地址转换成一个规范 IPv4 字符串，再判定是否属于 127.0.0.0/8，这些变体就无法绕过。'],
                    ['title' => '默认允许未知格式', 'body' => '代码没有采用“解析失败即拒绝”的默认策略，未知表示形式会继续进入请求阶段。'],
                ],
                'keyGap' => '缺少“解析失败即拒绝”的严格地址归一化流程，最终 IP 没有成为唯一安全判断对象。',
            ],
            'successFlag' => 'FLAG{SSRF_ADVANCED_IP_ENCODING}',
        ],
        9 => [
            'id' => 9,
            'key' => 'mixed-dns',
            'title' => '混合 DNS 记录',
            'difficulty' => '进阶',
            'summary' => '同一个域名同时返回公网和内网 A 记录，校验只看了第一条。',
            'concept' => 'DNS 一次查询可以返回多条地址。如果安全检查只验证第一条，而 HTTP 客户端选择另一条，安全结论必然失真。',
            'goal' => '让双记录 CDN 域名通过 DNS 校验，并触发内部混合 DNS 目标。',
            'targetLabel' => 'media-2f9c.dual-cdn.ssrf.lab:8081',
            'target' => 'http://media-2f9c.dual-cdn.ssrf.lab:8081/internal/dns-mixed',
            'codeLabel' => 'DnsGuard.php / MediaFetcher.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：DNS 一次查询可能返回多条 A 记录。
 * 安全校验必须检查全部答案，不能只看第一条。
 */
// 业务场景：合作伙伴 CDN 域名需要先检查 DNS
$url   = (string) $request->input('media_url');
$parts = parse_url($url);
$host  = strtolower((string) ($parts['host'] ?? ''));

if (!str_ends_with($host, '.dual-cdn.ssrf.lab')) {
    return response()->json(['error' => 'Unsupported CDN'], 422);
}

// dns_get_record 返回一个数组，可能有多个公网或内网地址。
$records = dns_get_record($host, DNS_A);
$firstIp = (string) ($records[0]['ip'] ?? '');

// 错误：只检查索引 0，没有检查后面的 127.0.0.1。
if (!filter_var(
    $firstIp,
    FILTER_VALIDATE_IP,
    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
)) {
    return response()->json(['error' => 'Internal CDN address'], 403);
}

// HTTP 客户端可能选择同一应答中的另一条记录并连接内网。
$body = (new MediaFetcher())->get($url);
return response()->json(['body' => $body]);
PHP,
            'filter' => 'DNS 检查：只读取第一条 A 记录，203.0.113.88 为公网地址时放行。',
            'hints' => [
                'DNS 查询可能同时返回多个 A 记录。',
                '第一条是 203.0.113.88，后面还有一条 127.0.0.1。',
                '提交：http://media-2f9c.dual-cdn.ssrf.lab:8081/internal/dns-mixed',
            ],
            'answerSteps' => [
                '使用受测 CDN 下的任意子域名。',
                '安全检查读取第一条公网记录并放行。',
                'HTTP 客户端连接另一条回环记录，进入内部服务。',
            ],
            'defense' => '解析全部 A 和 AAAA 记录；任意一条属于回环、私网或保留地址时整体拒绝，并固定实际连接的 IP。',
            'cause' => [
                'summary' => '漏洞来自不完整 DNS 结果检查：安全层只验证一个答案，而连接层可能选择另一个答案。',
                'points' => [
                    ['title' => '只检查第一条 DNS 记录', 'body' => 'dns_get_record 返回数组后直接读取索引 0，后续公网与内网混合记录完全没有进入判断。'],
                    ['title' => '连接层拥有独立选择权', 'body' => 'HTTP 客户端可能按轮询、优先级或连接失败重试选择其他 A 记录，因此校验结论不能代表最终连接。'],
                    ['title' => '没有拒绝混合答案', 'body' => '只要任意一条记录指向内部地址，该域名就不可信。代码却把“第一条安全”当成“整个域名安全”。'],
                    ['title' => '固定 IP 缺失', 'body' => '即使所有记录都检查过，也必须把选中的 IP 固定给本次连接，否则后续查询仍可能变化。'],
                ],
                'keyGap' => '安全判断没有覆盖全部 DNS 答案，也没有把批准结果固定到真实网络连接。',
            ],
            'successFlag' => 'FLAG{SSRF_MIXED_DNS_ANSWERS}',
        ],
        10 => [
            'id' => 10,
            'key' => 'multihop',
            'title' => '多级重定向',
            'difficulty' => '进阶',
            'summary' => '首跳与中间跳都位于公开服务，最后一跳才进入内网。',
            'concept' => '重定向链可以逐步改变目标。只检查初始 URL 或第一跳，仍然无法保证最终请求地址安全。',
            'goal' => '通过公开服务的两级跳转读取内部管理标记。',
            'targetLabel' => '公开多级跳转 :8083',
            'target' => 'http://127.0.0.1:8083/redirect/chain?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin',
            'codeLabel' => 'LinkPreviewController.php / RedirectChain.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：重定向会改变请求目标。
 * 一次校验只能证明当前 URL 安全，不能证明所有 Location 安全。
 */
// 业务场景：链接预览需要跟随合作伙伴页面跳转
$url   = (string) $request->input('preview_url');
$parts = parse_url($url);
$host  = (string) ($parts['host'] ?? '');
$port  = (int) ($parts['port'] ?? 0);

if ($host !== '127.0.0.1' || $port !== 8083) {
    return response()->json(['error' => 'Only public preview service'], 403);
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    // 自动跟随所有 Location，业务代码无法逐个检查跳转目标。
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 4,
    CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
]);

$body = curl_exec($ch);
return response()->json(['preview' => $body]);

// 公开服务：/redirect/chain
// 第一跳 -> /redirect/final -> 内部管理服务
PHP,
            'filter' => '首跳限制：只能从 127.0.0.1:8083/redirect/chain 开始。',
            'hints' => [
                '不要只看第一层 302，继续观察后续 Location。',
                '公开服务提供了 /redirect/chain 和 /redirect/final。',
                '提交：http://127.0.0.1:8083/redirect/chain?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin',
            ],
            'answerSteps' => [
                '第一跳使用允许的公开重定向链入口。',
                '客户端依次跟随 /redirect/final 和内部管理地址。',
                '多级跳转完成后读取内部 /admin 响应。',
            ],
            'defense' => '禁用自动重定向，手动处理每一个 Location；每次跳转都重新解析、校验并限制协议、Host、端口和 IP。',
            'cause' => [
                'summary' => '根因是请求生命周期中的信任没有延续：初始 URL 合法，但后续重定向目标重新获得了未验证的网络访问能力。',
                'points' => [
                    ['title' => '只校验链首地址', 'body' => '代码只确认第一跳属于公开服务，没有分析 Location 链中的后续地址。'],
                    ['title' => 'HTTP 客户端自动跟随', 'body' => 'CURLOPT_FOLLOWLOCATION 让客户端在业务逻辑之外继续发起请求，安全校验无法自然覆盖每一次跳转。'],
                    ['title' => '公开服务成为信任跳板', 'body' => '攻击者不需要直接控制内部网络，只需要让公开服务返回 302，就能借业务服务器进入内网。'],
                    ['title' => '跳转次数没有安全语义', 'body' => '限制最多 4 次跳转只能防止无限循环，不能保证这 4 个目标都在允许范围内。'],
                ],
                'keyGap' => '没有把每次重定向都当成一次全新的安全决策。',
            ],
            'successFlag' => 'FLAG{SSRF_MULTIHOP_REDIRECT}',
        ],
        11 => [
            'id' => 11,
            'key' => 'header',
            'title' => 'Header 驱动 SSRF',
            'difficulty' => '进阶',
            'summary' => 'Webhook 基地址是固定的，但请求头中的 Host 被直接拼进了内部请求。',
            'concept' => 'SSRF 不一定来自显式 URL 参数。只要业务会把某个 Header 当作地址使用，攻击者就可能通过代理头控制请求目标。',
            'goal' => '通过 X-Forwarded-Host 让 Webhook 请求进入内部服务。',
            'targetLabel' => 'Webhook 基地址 :8080',
            'target' => 'http://127.0.0.1:8080/webhook/test',
            'extraFields' => [
                ['key' => 'headerHost', 'label' => 'X-Forwarded-Host', 'placeholder' => '127.0.0.1:8081'],
            ],
            'codeLabel' => 'WebhookController.php / ForwardedHostResolver.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：SSRF 的输入不一定叫 url。
 * Host、X-Forwarded-Host、Origin 等 Header 也可能被拼成网络地址。
 */
// 业务场景：测试 Webhook 时允许反向代理传入目标 Host
$baseUrl = (string) $request->input('base_url');
$parts   = parse_url($baseUrl);

if (($parts['host'] ?? '') !== '127.0.0.1'
    || (int) ($parts['port'] ?? 0) !== 8080) {
    return response()->json(['error' => 'Invalid webhook base'], 403);
}

// 代理头只是代理链的元数据，不应当直接成为网络目标。
$forwardedHost = (string) $request->header('X-Forwarded-Host');
$target = 'http://' . $forwardedHost . '/internal/webhook';

$body = (new WebhookClient())->get($target);
return response()->json(['result' => $body]);
PHP,
            'filter' => '基地址校验：只允许 http://127.0.0.1:8080/webhook/test；X-Forwarded-Host 未校验。',
            'hints' => [
                '第一个输入只代表 Webhook 业务入口，不代表最终目标。',
                '把 X-Forwarded-Host 设置为内部服务地址。',
                'Base URL 使用默认值，Header 填 127.0.0.1:8081。',
            ],
            'answerSteps' => [
                '保留允许的 Webhook 基地址。',
                '在 X-Forwarded-Host 中填写 127.0.0.1:8081。',
                '业务把它拼成内部 Webhook 地址并发起请求。',
            ],
            'defense' => '不要把 Host、X-Forwarded-Host、Origin 等请求头直接当 URL；如果必须使用，按完整目标地址执行同样的协议、Host、端口和 IP 校验。',
            'cause' => [
                'summary' => '根因是信任了错误的地址来源：安全校验只覆盖 base_url，真正的目标却来自一个未验证的请求头。',
                'points' => [
                    ['title' => '显式 URL 与隐式目标分离', 'body' => '用户看到的是合法 base_url，实际请求目标由 X-Forwarded-Host 决定，安全校验没有覆盖这个隐式输入。'],
                    ['title' => '反向代理头被业务信任', 'body' => 'X-Forwarded-Host 本来是给代理链传递原始 Host 的元数据，却被直接拼入 HTTP 客户端的目标地址。'],
                    ['title' => 'Header 缺少格式和网络校验', 'body' => '代码没有限制 Header 只能是允许域名，也没有检查最终解析 IP 是否属于内部网段。'],
                    ['title' => '日志容易隐藏真实目标', 'body' => '业务日志如果只记录 base_url，会遗漏真正被访问的内部地址，增加发现和追踪难度。'],
                ],
                'keyGap' => '没有识别出 Header 也是 URL 输入源，安全策略只覆盖了表单参数。',
            ],
            'successFlag' => 'FLAG{SSRF_HEADER_DRIVEN}',
        ],
        12 => [
            'id' => 12,
            'key' => 'blind',
            'title' => '盲 SSRF 回调',
            'difficulty' => '进阶',
            'summary' => '业务不返回目标响应，但攻击者仍能通过外部回调确认请求已发出。',
            'concept' => 'SSRF 不要求读取响应。只要能观察到 DNS 查询、HTTP 回调或响应时间变化，就能确认服务端请求存在并被利用。',
            'goal' => '让报表导出服务访问回调监听器，并在靶场中确认盲请求记录。',
            'targetLabel' => '回调监听 :8084',
            'target' => 'http://127.0.0.1:8084/callback?token=blind-level12',
            'codeLabel' => 'ReportExportController.php / BlindCallbackService.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：没有回显也可能存在 SSRF。
 * 回调服务、DNS 查询和响应时间都可以作为观察信道。
 */
// 业务场景：导出报表时通知外部任务系统
$callbackUrl = (string) $request->input('callback_url');

if (!str_starts_with($callbackUrl, 'http://127.0.0.1:8084/callback')) {
    return response()->json(['error' => 'Invalid callback'], 422);
}

// 盲请求：业务不返回目标响应，但连接和请求仍然发生。
$client = new AsyncHttpClient();
$client->get($callbackUrl, [
    'timeout' => 3,
    'return_body' => false,
]);

return response()->noContent();

// 回调服务仍然记录了：
// token=blind-level12
// remote=127.0.0.1
PHP,
            'filter' => '回调地址限制：只允许 127.0.0.1:8084/callback。',
            'hints' => [
                '业务不返回目标正文，但服务端仍然发出了请求。',
                '靶场的回调监听器会记录 token。',
                '提交：http://127.0.0.1:8084/callback?token=blind-level12',
            ],
            'answerSteps' => [
                '提交允许范围内的回调 URL。',
                '业务异步请求回调服务但不回显目标正文。',
                '靶场通过回调记录确认盲 SSRF 已成功触发。',
            ],
            'defense' => '对盲 SSRF 使用独立出站代理和网络策略，记录完整目标；监控 DNS、回调域名和异常连接时间，不能只依赖响应内容判断风险。',
            'cause' => [
                'summary' => '根因仍是服务端可以访问用户指定的地址，只是响应不回显，使危害从读取数据变成了确认内部可达并触发副作用。',
                'points' => [
                    ['title' => '无回显不等于无请求', 'body' => '业务通过 return_body=false 隐藏目标响应，但 HTTP 客户端仍然建立连接并发送请求。'],
                    ['title' => '回调监听器形成侧信道', 'body' => '攻击者控制的 DNS 或 HTTP 服务可以记录 token、时间和来源，足以证明盲 SSRF 存在。'],
                    ['title' => '异步任务缺失出站控制', 'body' => '后台任务常被视为低风险区域，却通常拥有更宽松的网络权限和更少的目标校验。'],
                    ['title' => '副作用可能比读数据更危险', 'body' => '即使无法读取响应，请求本身也可能触发内部任务、状态变更或资源消耗。'],
                ],
                'keyGap' => '安全策略仍然依赖响应回显来识别风险，没有对出站连接本身做限制和审计。',
            ],
            'successFlag' => 'FLAG{SSRF_BLIND_CALLBACK}',
        ],
        13 => [
            'id' => 13,
            'key' => 'gopher',
            'title' => 'Gopher 协议跳板',
            'difficulty' => '高阶',
            'summary' => '运营素材采集器支持 gopher，业务允许原始字节流进入内部 TCP 服务。',
            'concept' => '素材采集器原本只应下载图片和网页，但 gopher 可以把任意字符串发送到 TCP 服务，可能操纵 Redis、Memcached 等非 HTTP 内部协议。',
            'goal' => '使用 gopher 让素材采集器向模拟内部 TCP 服务发送命令并读取 flag。',
            'targetLabel' => '素材采集 TCP :6380',
            'target' => 'gopher://127.0.0.1:6380/_GET%20flag%0D%0A',
            'codeLabel' => 'CreativeCollector.php / MockRedisService.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：协议决定了客户端如何解释 URL。
 * gopher:// 会把数据直接发送到 TCP 端口，而不是发送 HTTP 请求。
 */
// 业务场景：通用远程资源抓取器
$url = (string) $request->input('resource_url');
// scheme 是协议名，例如 http、https、file、gopher。
$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

// 错误：只禁止 file，没有使用 HTTP/HTTPS 协议白名单
if ($scheme === 'file') {
    return response()->json(['error' => 'File protocol blocked'], 403);
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 4,
    // 只要客户端允许 gopher，就会产生原始 TCP 字节流。
    CURLOPT_PROTOCOLS => CURLPROTO_GOPHER
        | CURLPROTO_HTTP
        | CURLPROTO_HTTPS,
]);

$body = curl_exec($ch);
return response()->json(['body' => $body]);

// 模拟内部 TCP 服务监听 127.0.0.1:6380
// 收到 GET flag 后返回 FLAG{...}
PHP,
            'filter' => '协议检查：只拦截 file，gopher 仍被 HTTP 客户端允许。',
            'hints' => [
                '注意 curl 支持的协议列表远不止 HTTP。',
                'gopher 会把 URL 中的编码字节发送到目标 TCP 端口。',
                '提交：gopher://127.0.0.1:6380/_GET%20flag%0D%0A',
            ],
            'answerSteps' => [
                '使用 gopher URL 指向模拟内部 TCP 服务。',
                'URL 中的 %20、%0D、%0A 会被解码为原始字节。',
                '模拟服务返回包含 flag 的响应。',
            ],
            'defense' => '只启用业务需要的 HTTP/HTTPS 协议；显式设置客户端协议白名单，禁止 gopher、file、dict 等能力，并限制出站端口。',
            'cause' => [
                'summary' => '根因是协议策略采用黑名单且不足，通用的 curl 能力把 HTTP SSRF 扩展成了任意 TCP 字节流注入。',
                'points' => [
                    ['title' => '只禁止 file 仍然过于宽泛', 'body' => 'gopher、dict、ftp 等协议没有从客户端能力中移除，未知协议默认仍可能被启用。'],
                    ['title' => '协议改变了请求语义', 'body' => 'HTTP 客户端收到 gopher URL 后不会发送 HTTP 请求，而是把解码后的字节直接写入 TCP 连接。'],
                    ['title' => '内部非 HTTP 服务暴露', 'body' => 'Redis、Memcached 等内部服务通常只依赖网络隔离，一旦业务服务器能发送原始字节，就可能被直接操作。'],
                    ['title' => '业务未限制出站端口', 'body' => '代码允许访问任意主机和端口，没有把目标限制在 Web 资源所需的 80、443 等端口。'],
                ],
                'keyGap' => '协议与端口都没有使用最小能力白名单，HTTP 客户端变成了通用 TCP 客户端。',
            ],
            'successFlag' => 'FLAG{SSRF_GOPHER_PIVOT}',
        ],
        14 => [
            'id' => 14,
            'key' => 'metadata',
            'title' => '云元数据变体',
            'difficulty' => '高阶',
            'summary' => '黑名单拦住了经典元数据 IP，却遗漏了云厂商内部域名。',
            'concept' => '不同云环境使用不同元数据地址和内部 DNS。只屏蔽 169.254.169.254 无法覆盖 GCP、Azure 或其他提供商的内部入口。',
            'goal' => '通过云厂商内部元数据域名读取模拟访问令牌。',
            'targetLabel' => 'metadata.google.internal:8082',
            'target' => 'http://metadata.google.internal:8082/computeMetadata/v1/instance/service-accounts/default/token',
            'codeLabel' => 'CloudAssetImporter.php / MetadataHostPolicy.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：云元数据不只有一个 IP。
 * 不同云厂商可能使用内部域名、链路本地地址或特殊 DNS。
 */
// 业务场景：从云存储 URL 导入用户资源
$url = (string) $request->input('asset_url');

// 错误：只拦截经典 AWS 元数据 IP
if (str_contains($url, '169.254.169.254')) {
    return response()->json(['error' => 'Metadata IP blocked'], 403);
}

$parts = parse_url($url);
$host  = strtolower((string) ($parts['host'] ?? ''));

// 允许云厂商内部域名，但没有解析到最终 IP。
if (!in_array($host, [
    'metadata.google.internal',
    'instance-data.ec2.internal',
    'metadata.azure.internal',
], true)) {
    return response()->json(['error' => 'Unsupported cloud host'], 422);
}

$body = (new CloudHttpClient())->get($url);
return response()->json(['metadata' => $body]);
PHP,
            'filter' => '元数据黑名单：只拦截 169.254.169.254，允许云厂商内部域名。',
            'hints' => [
                '经典 IP 被拦截，不代表元数据入口只有一个。',
                '业务白名单里包含云厂商内部域名。',
                '提交：http://metadata.google.internal:8082/computeMetadata/v1/instance/service-accounts/default/token',
            ],
            'answerSteps' => [
                '改用云厂商内部元数据域名。',
                '业务认为域名属于受支持云环境并放行。',
                '实验边界把域名映射到本地 8082 模拟元数据服务。',
            ],
            'defense' => '云元数据防护不能依赖 IP 黑名单；应阻断整个链路本地地址、云厂商内部 DNS 和元数据域名，并在网络层禁用实例访问元数据。',
            'cause' => [
                'summary' => '根因是把单个元数据 IP 当成全部攻击面，忽略了不同云厂商的 DNS 名称和内部路由。',
                'points' => [
                    ['title' => '黑名单不具备跨云覆盖能力', 'body' => '169.254.169.254 只是部分云环境的经典入口，metadata.google.internal 等域名同样可能解析到内部元数据。'],
                    ['title' => '内部域名被业务主动放行', 'body' => '白名单把云厂商域名视为可信，却没有解析这些域名并检查最终 IP。'],
                    ['title' => '没有区分业务域名与基础设施域名', 'body' => '云存储导入只需要对象存储域名，不应该允许访问实例控制平面和凭据服务。'],
                    ['title' => '网络层缺少元数据隔离', 'body' => '如果实例网络允许服务访问元数据，应用层黑名单一旦遗漏就会泄露临时凭据。'],
                ],
                'keyGap' => '云元数据防护仅覆盖一个已知 IP，没有按域名、解析 IP、云厂商和网络出口建立完整策略。',
            ],
            'successFlag' => 'FLAG{SSRF_CLOUD_METADATA_VARIANT}',
        ],
        15 => [
            'id' => 15,
            'key' => 'renderer',
            'title' => '渲染器 SSRF',
            'difficulty' => '高阶',
            'summary' => '首跳只抓取公开页面，但页面渲染器随后自动加载了内网图片资源。',
            'concept' => '链接预览、PDF 生成、网页截图等服务会解析 HTML 并继续请求图片、样式、脚本和字体。第二次请求经常绕过原始 URL 校验。',
            'goal' => '让渲染器加载公开页面中的内网图片资源。',
            'targetLabel' => '渲染器页面 :8084',
            'target' => 'http://127.0.0.1:8084/renderer-page?target=http%3A%2F%2F127.0.0.1%3A8081%2Finternal%2Frenderer',
            'codeLabel' => 'LinkPreviewRenderer.php / ImageLoader.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：解析 HTML 会产生“二次请求”。
 * 页面 URL 合法，不代表 img、link、script 中的资源地址合法。
 */
// 业务场景：生成外部分享链接的预览卡片
$pageUrl = (string) $request->input('page_url');
$parts   = parse_url($pageUrl);

if (($parts['host'] ?? '') !== '127.0.0.1'
    || (int) ($parts['port'] ?? 0) !== 8084) {
    return response()->json(['error' => 'Preview page not allowed'], 403);
}

$html = (new HtmlFetcher())->get($pageUrl);
// 从页面内容中提取图片地址。这个地址来自远程内容，也是不可信输入。
preg_match('/<img\b[^>]*\bsrc=["\']([^"\']+)/i', $html, $match);

$imageUrl = html_entity_decode($match[1] ?? '');

// 错误：二次资源请求没有重新执行目标校验
$image = (new ImageLoader())->get($imageUrl);

return response()->json([
    'page' => $pageUrl,
    'image' => $image,
]);
PHP,
            'filter' => '页面限制：只允许提交 127.0.0.1:8084/renderer-page，但未检查页面内的 img src。',
            'hints' => [
                '渲染器会继续加载 HTML 中的图片、CSS 和字体。',
                '页面地址合法不代表页面内资源合法。',
                '提交：http://127.0.0.1:8084/renderer-page?target=http%3A%2F%2F127.0.0.1%3A8081%2Finternal%2Frenderer',
            ],
            'answerSteps' => [
                '提交受信任的渲染器页面地址。',
                '页面返回 HTML，其中的 img src 指向内部服务。',
                'ImageLoader 没有复验目标，直接抓取内网资源。',
            ],
            'defense' => '对渲染器加载的每一个资源重新执行安全策略；默认拒绝内网资源，限制协议和域名，并在独立网络沙箱中运行渲染器。',
            'cause' => [
                'summary' => '漏洞是二次请求绕过：用户输入的直接 URL 合法，但渲染器从页面内容中提取出的资源 URL 成了新的未校验输入。',
                'points' => [
                    ['title' => '只校验页面 URL', 'body' => '业务确认 renderer-page 合法后就认为整个预览过程安全，没有把后续资源 URL 纳入校验。'],
                    ['title' => '页面内容可以控制资源地址', 'body' => 'HTML 中的 img、link、iframe 和 CSS 都能触发额外请求，攻击者可以通过页面内容指定内部目标。'],
                    ['title' => '渲染器拥有更宽的网络能力', 'body' => '无头浏览器和渲染服务通常需要加载多种资源，出站范围比普通 HTTP API 更广，但也更容易被滥用。'],
                    ['title' => '二次请求缺少来源标记', 'body' => '图片加载请求与普通用户请求没有区别，日志和权限系统可能无法识别它来自不可信页面。'],
                ],
                'keyGap' => '安全边界只覆盖第一跳页面，没有覆盖渲染器产生的所有子资源请求。',
            ],
            'successFlag' => 'FLAG{SSRF_RENDERER_SECONDARY_REQUEST}',
        ],
        16 => [
            'id' => 16,
            'key' => 'business',
            'title' => 'RSS 导入 SSRF',
            'difficulty' => '高阶',
            'summary' => 'RSS 订阅地址合法，但导入器随后抓取了订阅内容中的 enclosure 内网地址。',
            'concept' => '业务入口 SSRF 常出现在 RSS、Webhook、OAuth、翻译和图片导入。攻击者控制的远程内容可以携带新的 URL，诱导业务发起第二次请求。',
            'goal' => '通过恶意 RSS 订阅中的 enclosure 访问内部导入目标。',
            'targetLabel' => 'RSS 订阅 :8084',
            'target' => 'http://127.0.0.1:8084/malicious-feed.xml',
            'codeLabel' => 'RssImportService.php / FeedParser.php',
            'snippet' => <<<'PHP'
<?php
/*
 * 学习目标：订阅源内容同样可以携带 URL。
 * feed_url 安全，不代表 enclosure、link 或媒体地址安全。
 */
// 业务场景：导入合作伙伴 RSS 订阅
$feedUrl = (string) $request->input('feed_url');
$parts   = parse_url($feedUrl);

if (($parts['host'] ?? '') !== '127.0.0.1'
    || (int) ($parts['port'] ?? 0) !== 8084) {
    return response()->json(['error' => 'Feed source not allowed'], 403);
}

$xml = (new FeedFetcher())->get($feedUrl);

// 错误：直接信任远程 XML 中的 enclosure 地址。
$enclosureUrl = FeedParser::firstEnclosure($xml);
$resource = (new RemoteDownloader())->get($enclosureUrl);

return response()->json([
    'feed' => $feedUrl,
    'enclosure' => $enclosureUrl,
    'resource' => $resource,
]);
PHP,
            'filter' => '订阅源限制：只允许提交 127.0.0.1:8084/malicious-feed.xml，未校验 enclosure。',
            'hints' => [
                '订阅源地址安全，不代表订阅内容里的资源地址安全。',
                '检查 RSS XML 中的 enclosure url。',
                '提交：http://127.0.0.1:8084/malicious-feed.xml',
            ],
            'answerSteps' => [
                '提交受测的 RSS 订阅源。',
                '解析器读取订阅中的 enclosure 地址。',
                '下载器未复验 enclosure，直接访问内部导入服务。',
            ],
            'defense' => '把所有由远程内容提供的 URL 都视为新输入，对每个 enclosure、图片和附件重新执行目标校验；导入器应运行在限制出站网络的沙箱中。',
            'cause' => [
                'summary' => '根因是业务只信任了订阅源地址，却信任了订阅内容中的二级资源地址。',
                'points' => [
                    ['title' => '信任从一级输入传递到二级输入', 'body' => 'feed_url 经过校验后，解析器从响应 XML 中提取 enclosure，并把远程内容当成可信配置。'],
                    ['title' => 'XML 可以携带任意资源地址', 'body' => 'enclosure、media:content、link 等字段都可能导致下载器发起后续请求，攻击者只需要控制订阅内容。'],
                    ['title' => '下载器复用高权限网络身份', 'body' => '导入器为了下载附件直接使用业务服务器网络，没有独立出站代理或内网访问限制。'],
                    ['title' => '日志只记录原始订阅地址', 'body' => '如果只记录 feed_url，真实访问的 enclosure 内网目标可能不会被安全监控发现。'],
                ],
                'keyGap' => '没有对所有由远程内容产生的 URL 重新执行安全校验和网络边界控制。',
            ],
            'successFlag' => 'FLAG{SSRF_RSS_IMPORT}',
        ],
    ];
}

