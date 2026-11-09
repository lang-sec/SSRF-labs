<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 招商后台的品牌 Logo 同步。
 */
final class LogoImportController extends BusinessController
{
    public function import(): array
    {
        $logoUrl = $this->required('logo_url');

        // 只排除本地调试时最常用的两种写法。
        if (preg_match('/(?:localhost|127\.0\.0\.1)/i', $logoUrl) === 1) {
            return $this->reject('Logo 地址不在允许范围。', $logoUrl);
        }

        $response = $this->http->get($logoUrl);

        return $this->respond($response, '品牌 Logo 已同步。');
    }
}
