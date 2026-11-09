<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 知识库附件预览。
 */
final class AttachmentPreviewController extends BusinessController
{
    public function preview(): array
    {
        $attachmentUrl = $this->required('attachment_url');
        $scheme = strtolower((string) parse_url($attachmentUrl, PHP_URL_SCHEME));

        if (in_array($scheme, ['gopher', 'dict', 'ftp'], true)) {
            return $this->reject('不支持的附件协议。', $attachmentUrl);
        }

        $response = $scheme === 'file'
            ? $this->http->readFile($attachmentUrl)
            : $this->http->get($attachmentUrl);

        return $this->respond($response, '附件预览已生成。');
    }
}
