<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 合作伙伴媒体同步。
 */
final class PartnerMediaController extends BusinessController
{
    public function sync(): array
    {
        $mediaUrl = $this->required('media_url');
        $parts = parse_url($mediaUrl);
        $host = strtolower((string) ($parts['host'] ?? ''));

        if (!$this->network->isDualDnsHost($host)) {
            return $this->reject('媒体域名不在合作方白名单。', $mediaUrl);
        }

        $records = $this->dns->lookup($host);
        $firstIp = $records[0] ?? null;
        if ($firstIp === null || $this->network->isPrivateIp($firstIp)) {
            return $this->reject('媒体域名解析结果不可用。', $mediaUrl);
        }

        $response = $this->http->get($mediaUrl, ['resolveIp' => $records[1] ?? $firstIp]);

        return $this->respond($response, '合作伙伴媒体同步完成。');
    }
}
