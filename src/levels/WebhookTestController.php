<?php

declare(strict_types=1);

namespace SsrfLab\Levels;

use SsrfLab\Support\BusinessController;
use SsrfLab\Support\MissingInputException;

/**
 * Webhook 连通性测试。
 */
final class WebhookTestController extends BusinessController
{
    public function test(): array
    {
        $baseUrl = $this->required('base_url');
        $parts = parse_url($baseUrl);
        $host = (string) ($parts['host'] ?? '');
        $port = (int) ($parts['port'] ?? 0);
        $path = (string) ($parts['path'] ?? '');

        if ($host !== '127.0.0.1' || $port !== 8080 || $path !== '/webhook/test') {
            return $this->reject('Webhook 基地址不合法。', $baseUrl);
        }

        $forwardedHost = $this->header('X-Forwarded-Host');
        if ($forwardedHost === '') {
            throw new MissingInputException('X-Forwarded-Host header is required');
        }

        $target = 'http://' . $forwardedHost . '/internal/webhook';
        $response = $this->http->get($target);

        return $this->respond($response, 'Webhook 连通性测试完成。', null, $baseUrl);
    }
}
