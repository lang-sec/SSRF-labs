<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 报表导出完成通知。
 */
final class ReportExportController extends BusinessController
{
    public function export(): array
    {
        $callbackUrl = $this->required('callback_url');
        $response = $this->http->get($callbackUrl, ['timeout' => 10]);

        if ($response->blocked || !$response->ok) {
            return $this->respond($response, '报表导出请求已提交。');
        }

        $payload = json_decode($response->body, true);
        $dnsQueried = is_array($payload) && ($payload['dns_queried'] ?? false) === true;
        $internal = is_array($payload) ? ($payload['internal_fetch'] ?? null) : null;

        if (is_array($internal) && (int) ($internal['status'] ?? 0) > 0) {
            $message = sprintf(
                '盲请求已发出；目标访问了内部服务 %s，HTTP %d，%d 字节。请到 dnslog 查看 DNS 记录。',
                (string) ($internal['url'] ?? ''),
                (int) ($internal['status'] ?? 0),
                (int) ($internal['bytes'] ?? 0)
            );
        } elseif ($dnsQueried) {
            $message = '盲请求已发出；目标执行了 DNS 查询。请到 dnslog 查看解析记录。';
        } else {
            $message = '请求已发出，但验证端点没有确认 DNS 查询。';
        }

        return $this->respond($response->withBody($message), '报表导出任务已提交。', $dnsQueried);
    }
}
