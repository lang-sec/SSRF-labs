<?php

declare(strict_types=1);

namespace SsrfLab\Support;

abstract class BusinessController
{
    protected HttpClient $http;
    protected DnsResolver $dns;
    protected NetworkGuard $network;

    public function __construct(
        protected readonly int $level,
        protected readonly array $input,
    ) {
        $this->http = new HttpClient($level);
        $this->dns = new DnsResolver();
        $this->network = new NetworkGuard();
    }

    protected function input(string $key, string $default = ''): string
    {
        return trim((string) ($this->input[$key] ?? $default));
    }

    protected function required(string $key): string
    {
        $value = $this->input($key);
        if ($value === '') {
            throw new MissingInputException('Missing required parameter: ' . $key);
        }
        if (strlen($value) > 2048) {
            throw new MissingInputException('URL 长度不能超过 2048 字符');
        }

        return $value;
    }

    protected function header(string $name): string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));

        return trim((string) ($_SERVER[$key] ?? ''));
    }

    protected function reject(string $message, string $logUrl = ''): array
    {
        return [
            'blocked' => true,
            'message' => $message,
            'logUrl' => $logUrl,
        ];
    }

    protected function respond(HttpResponse $response, string $message, ?bool $solved = null, ?string $logUrl = null): array
    {
        return [
            'response' => $response,
            'message' => $message,
            'solved' => $solved,
            'logUrl' => $logUrl ?? $response->target,
        ];
    }
}
