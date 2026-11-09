<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 站外链接预览。
 */
final class LinkPreviewController extends BusinessController
{
    public function preview(): array
    {
        $previewUrl = $this->required('preview_url');
        $parts = parse_url($previewUrl);
        $host = (string) ($parts['host'] ?? '');
        $port = (int) ($parts['port'] ?? 0);

        if ($host !== '127.0.0.1' || $port !== 8083) {
            return $this->reject('仅允许预览公开服务地址。', $previewUrl);
        }

        $response = $this->http->get($previewUrl, [
            'followRedirects' => true,
            'maxRedirects' => 4,
        ]);

        return $this->respond($response, '链接预览已生成。');
    }
}
