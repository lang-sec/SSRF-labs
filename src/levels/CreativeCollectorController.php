<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 运营素材采集器。
 */
final class CreativeCollectorController extends BusinessController
{
    public function collect(): array
    {
        $resourceUrl = $this->required('resource_url');
        $scheme = strtolower((string) parse_url($resourceUrl, PHP_URL_SCHEME));

        if ($scheme === 'file') {
            return $this->reject('不支持本地文件素材。', $resourceUrl);
        }

        $response = $scheme === 'gopher'
            ? $this->http->gopher($resourceUrl)
            : $this->http->get($resourceUrl);

        return $this->respond($response, '运营素材采集完成。');
    }
}
