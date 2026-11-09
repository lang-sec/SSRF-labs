<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 聊天窗口的富链接预览。
 */
final class RichPreviewController extends BusinessController
{
    public function preview(): array
    {
        $previewUrl = $this->required('preview_url');
        $parts = parse_url($previewUrl);
        $host = (string) ($parts['host'] ?? '');
        $port = (int) ($parts['port'] ?? 0);
        $path = (string) ($parts['path'] ?? '');

        if ($host !== '127.0.0.1' || $port !== 8083 || $path !== '/redirect/chain') {
            return $this->reject('仅允许公开的多级跳转入口。', $previewUrl);
        }

        $response = $this->http->get($previewUrl, [
            'followRedirects' => true,
            'maxRedirects' => 4,
        ]);

        return $this->respond($response, '聊天链接预览已生成。');
    }
}
