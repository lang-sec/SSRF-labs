<?php

declare(strict_types=1);

function lab_business_scenarios(): array
{
    $scenarios = [
        1 => [
            'feature' => '目标可达性验证',
            'entry' => 'POST /products/import-image',
            'workflow' => ['提交验证端点根路径', '服务端向 10.220.2.6:8080 发起请求', '响应返回 MD5'],
            'impact' => '服务端替调用方请求了外部验证端点，并把目标响应带回。',
        ],
        2 => [
            'feature' => '品牌 Logo 自动抓取',
            'entry' => 'POST /merchants/import-logo',
            'workflow' => ['招商后台提交 Logo 地址', '服务端检查常见回环字符串', '图片服务下载品牌资源'],
            'impact' => '黑名单只覆盖少量字符串，品牌导入功能仍可被用来连接内部管理服务。',
        ],
        3 => [
            'feature' => '营销落地页素材检查',
            'entry' => 'POST /campaigns/check-asset',
            'workflow' => ['运营提交活动素材 URL', '系统检查 shop.local 关键词', '素材服务抓取远程内容'],
            'impact' => '运营输入通过关键词校验后，素材服务会以业务服务器身份访问内部调试接口。',
        ],
        4 => [
            'feature' => '站外链接预览',
            'entry' => 'POST /messages/link-preview',
            'workflow' => ['用户粘贴站外链接', '预览服务校验公开入口', 'HTTP 客户端跟随跳转获取页面'],
            'impact' => '公开链接首跳合法，但自动重定向会让预览服务最终读取内部管理页面。',
        ],
        5 => [
            'feature' => 'CDN 头像预览',
            'entry' => 'POST /profiles/avatar-preview',
            'workflow' => ['用户提交 CDN 头像地址', '业务检查首次 DNS 结果', '图片客户端重新解析并下载'],
            'impact' => '攻击者控制的短 TTL DNS 可以让校验看到公网 IP，而连接落到回环地址。',
        ],
        6 => [
            'feature' => '知识库附件预览',
            'entry' => 'POST /knowledge-base/preview-attachment',
            'workflow' => ['员工提交附件地址', '预览服务检查危险协议黑名单', '服务端读取远程或本地资源'],
            'impact' => '攻击者利用遗漏的 file:// 协议，把附件预览功能变成服务器本地文件读取。',
        ],
        7 => [
            'feature' => '社交头像同步',
            'entry' => 'POST /profiles/sync-avatar',
            'workflow' => ['用户提交第三方头像 URL', '控制器检查 URL 可用域名', '远程资源客户端下载头像'],
            'impact' => '控制器把 userinfo 误认为 Host，头像同步请求实际落到内部服务。',
        ],
        8 => [
            'feature' => '静态资源迁移',
            'entry' => 'POST /admin/assets/migrate',
            'workflow' => ['运维提交旧资源地址', '迁移器执行旧地址黑名单', '资源下载器归一化并抓取文件'],
            'impact' => '迁移器接受历史 IP 表示法，黑名单被绕过并继续访问回环地址。',
        ],
        9 => [
            'feature' => '合作伙伴媒体同步',
            'entry' => 'POST /partners/media-sync',
            'workflow' => ['运营提交合作伙伴 CDN 域名', '业务读取第一条 DNS A 记录', '媒体抓取器选择连接地址'],
            'impact' => '同一域名混合公网与内网记录时，校验和实际连接可能选择不同 IP。',
        ],
        10 => [
            'feature' => '聊天链接预览',
            'entry' => 'POST /messages/rich-preview',
            'workflow' => ['用户粘贴预览链接', '预览服务检查首跳服务', '客户端连续跟随多次重定向'],
            'impact' => '公开重定向链的最后跳可以进入内网，而首跳校验始终显示合法。',
        ],
        11 => [
            'feature' => 'Webhook 连通性测试',
            'entry' => 'POST /webhook/test',
            'workflow' => ['运营填写 Webhook 基地址', '代理层传入 X-Forwarded-Host', '测试客户端拼接最终 Webhook URL'],
            'impact' => '显式 URL 合法，但代理 Header 控制实际目标，导致内部 Webhook 被访问。',
        ],
        12 => [
            'feature' => '无回显 SSRF 验证',
            'entry' => 'POST /reports/export',
            'workflow' => ['准备 dnslog 子域名', '提交带 host 参数的验证 URL', '验证端点发起真实 DNS 查询'],
            'impact' => '目标响应不回显，但 dnslog 平台可以确认请求已经发生。',
        ],
        13 => [
            'feature' => '运营素材采集器',
            'entry' => 'POST /marketing/collect-asset',
            'workflow' => ['运营提交远程素材 URL', '采集器检查少量危险协议', 'curl 按协议发送资源请求'],
            'impact' => 'gopher URL 会变成原始 TCP 字节流，采集器可能操作内部非 HTTP 服务。',
        ],
        14 => [
            'feature' => '云存储资源导入',
            'entry' => 'POST /cloud/import-asset',
            'workflow' => ['管理员提交云资源 URL', '导入器检查经典元数据 IP', '云 HTTP 客户端读取远程资源'],
            'impact' => '业务允许云厂商内部域名，SSRF 请求因此可以触达模拟元数据控制平面。',
        ],
        15 => [
            'feature' => '分享链接卡片生成',
            'entry' => 'POST /sharing/card',
            'workflow' => ['用户提交分享页面 URL', '渲染器抓取 HTML', '图片加载器自动请求页面子资源'],
            'impact' => '页面地址合法，但页面内容可以指定内网图片地址，绕过二次资源校验。',
        ],
        16 => [
            'feature' => '合作伙伴 RSS 导入',
            'entry' => 'POST /feeds/import',
            'workflow' => ['运营提交 RSS 地址', '导入器解析订阅 XML', '下载器抓取 enclosure 附件'],
            'impact' => '订阅源合法，但远程内容中的 enclosure 可以把下载器引向内网服务。',
        ],
    ];

    // 机器可读的业务接口元数据：前端、测试和路由注册表共用同一份定义。
    $routes = [
        1 => ['method' => 'POST', 'api' => '/products/import-image', 'param' => 'image_url', 'solveMode' => 'md5'],
        2 => ['method' => 'POST', 'api' => '/merchants/import-logo', 'param' => 'logo_url'],
        3 => ['method' => 'POST', 'api' => '/campaigns/check-asset', 'param' => 'asset_url'],
        4 => ['method' => 'POST', 'api' => '/messages/link-preview', 'param' => 'preview_url'],
        5 => ['method' => 'POST', 'api' => '/profiles/avatar-preview', 'param' => 'avatar_url'],
        6 => ['method' => 'POST', 'api' => '/knowledge-base/preview-attachment', 'param' => 'attachment_url'],
        7 => ['method' => 'POST', 'api' => '/profiles/sync-avatar', 'param' => 'avatar_url'],
        8 => ['method' => 'POST', 'api' => '/admin/assets/migrate', 'param' => 'asset_url'],
        9 => ['method' => 'POST', 'api' => '/partners/media-sync', 'param' => 'media_url'],
        10 => ['method' => 'POST', 'api' => '/messages/rich-preview', 'param' => 'preview_url'],
        11 => [
            'method' => 'POST',
            'api' => '/webhook/test',
            'param' => 'base_url',
            'header' => 'X-Forwarded-Host',
            'headerField' => 'headerHost',
        ],
        12 => ['method' => 'POST', 'api' => '/reports/export', 'param' => 'callback_url', 'solveMode' => 'dnslog'],
        13 => ['method' => 'POST', 'api' => '/marketing/collect-asset', 'param' => 'resource_url'],
        14 => ['method' => 'POST', 'api' => '/cloud/import-asset', 'param' => 'asset_url'],
        15 => ['method' => 'POST', 'api' => '/sharing/card', 'param' => 'page_url'],
        16 => ['method' => 'POST', 'api' => '/feeds/import', 'param' => 'feed_url'],
    ];

    foreach ($scenarios as $level => &$scenario) {
        $scenario = array_merge($scenario, $routes[$level] ?? []);
    }
    unset($scenario);

    return $scenarios;
}

