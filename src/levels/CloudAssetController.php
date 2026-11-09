<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 云存储资源导入。
 */
final class CloudAssetController extends BusinessController
{
    public function import(): array
    {
        $assetUrl = $this->required('asset_url');

        if (str_contains($assetUrl, '169.254.169.254')) {
            return $this->reject('元数据地址不允许访问。', $assetUrl);
        }

        $parts = parse_url($assetUrl);
        $host = strtolower((string) ($parts['host'] ?? ''));

        if (!$this->network->isCloudMetadataHost($host)) {
            return $this->reject('不支持的云资源域名。', $assetUrl);
        }

        $connectionIp = $this->dns->connectionIp($host);
        if ($connectionIp === null) {
            return $this->reject('云资源域名解析失败。', $assetUrl);
        }

        $response = $this->http->get($assetUrl, ['resolveIp' => $connectionIp]);

        return $this->respond($response, '云存储资源导入完成。');
    }
}
