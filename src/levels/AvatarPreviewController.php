<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * CDN 头像预览。
 */
final class AvatarPreviewController extends BusinessController
{
    public function preview(): array
    {
        $avatarUrl = $this->required('avatar_url');
        $parts = parse_url($avatarUrl);
        $host = strtolower((string) ($parts['host'] ?? ''));

        if (!$this->network->isRebindHost($host)) {
            return $this->reject('头像地址必须使用受信任的 CDN 域名。', $avatarUrl);
        }

        $validationIp = $this->dns->lookupOne($host);
        if ($validationIp === null || $this->network->isPrivateIp($validationIp)) {
            return $this->reject('头像 CDN 解析到内部地址，已拒绝。', $avatarUrl);
        }

        // 下载阶段使用独立的 DNS 解析结果。
        $connectionIp = $this->dns->connectionIp($host);
        if ($connectionIp === null) {
            return $this->reject('头像 CDN 解析失败。', $avatarUrl);
        }

        $response = $this->http->get($avatarUrl, ['resolveIp' => $connectionIp]);

        return $this->respond($response, '头像预览已生成。');
    }
}
