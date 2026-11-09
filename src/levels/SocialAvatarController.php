<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;

/**
 * 用户社交头像同步。
 */
final class SocialAvatarController extends BusinessController
{
    public function sync(): array
    {
        $avatarUrl = $this->required('avatar_url');
        $parts = parse_url($avatarUrl);
        $checkedHost = is_array($parts) ? (string) ($parts['user'] ?? '') : '';

        if ($checkedHost !== 'shop.local') {
            return $this->reject('头像来源域名不在白名单。', $avatarUrl);
        }

        $response = $this->http->get($avatarUrl);

        return $this->respond($response, '头像同步完成。');
    }
}
