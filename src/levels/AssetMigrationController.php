<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 静态资源迁移。
 */
final class AssetMigrationController extends BusinessController
{
    public function migrate(): array
    {
        $assetUrl = $this->required('asset_url');

        if (preg_match('/(?:localhost|127\.0\.0\.1|2130706433|0x7f000001)/i', $assetUrl) === 1) {
            return $this->reject('资源地址不在允许范围。', $assetUrl);
        }

        $response = $this->http->get($assetUrl);

        return $this->respond($response, '静态资源迁移完成。');
    }
}
