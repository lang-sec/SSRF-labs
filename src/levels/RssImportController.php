<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 合作伙伴 RSS 订阅导入。
 */
final class RssImportController extends BusinessController
{
    public function import(): array
    {
        $feedUrl = $this->required('feed_url');
        $feed = $this->http->get($feedUrl);

        if ($feed->blocked || !$feed->ok) {
            return $this->respond($feed, 'RSS 订阅抓取失败。');
        }

        if (preg_match('/<enclosure\b[^>]*\burl=["\']([^"\']+)["\']/i', $feed->body, $match) !== 1) {
            return $this->reject('RSS 订阅没有可导入的附件。', $feedUrl);
        }

        $enclosureUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $resource = $this->http->get($enclosureUrl);

        return $this->respond($resource, 'RSS 订阅导入完成。', null, $feedUrl);
    }
}
