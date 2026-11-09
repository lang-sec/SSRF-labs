<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 营销落地页的远程素材检查。
 */
final class CampaignAssetController extends BusinessController
{
    public function check(): array
    {
        $assetUrl = $this->required('asset_url');

        if (!str_contains($assetUrl, 'shop.local')) {
            return $this->reject('素材地址必须来自 shop.local。', $assetUrl);
        }

        $response = $this->http->get($assetUrl);

        return $this->respond($response, '素材检查完成。');
    }
}
