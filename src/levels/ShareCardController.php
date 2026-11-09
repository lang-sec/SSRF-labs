<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 分享链接卡片生成。
 */
final class ShareCardController extends BusinessController
{
    public function create(): array
    {
        $pageUrl = $this->required('page_url');
        $page = $this->http->get($pageUrl);

        if ($page->blocked || !$page->ok) {
            return $this->respond($page, '分享页面抓取失败。');
        }

        if (preg_match('/<img\b[^>]*\bsrc=["\']([^"\']+)["\']/i', $page->body, $match) !== 1) {
            return $this->reject('分享页面没有可用的封面图。', $pageUrl);
        }

        $imageUrl = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $image = $this->http->get($imageUrl);

        return $this->respond($image, '分享卡片已生成。', null, $pageUrl);
    }
}
