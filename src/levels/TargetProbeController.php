<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 商品图片导入前的目标可达性检查。
 */
final class TargetProbeController extends BusinessController
{
    public function probe(): array
    {
        $targetUrl = $this->required('image_url');
        $response = $this->http->get($targetUrl);

        $available = $response->ok
            && preg_match('/\b[a-f0-9]{32}\b/i', $response->body, $match) === 1;

        return $this->respond(
            $response,
            $available ? '目标返回 MD5，确认存在有回显 SSRF。' : '目标未返回 MD5。',
            $available
        );
    }
}
