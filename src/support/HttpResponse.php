<?php

declare(strict_types=1);

namespace SsrfLab\Support;

final class HttpResponse
{
    public function __construct(
        public readonly bool $ok,
        public readonly bool $blocked,
        public readonly string $method,
        public readonly int $status,
        public readonly string $body,
        public readonly string $target,
        public readonly string $finalUrl,
        public readonly ?string $resolvedIp,
        public readonly int $durationMs,
        public readonly string $error,
        public readonly string $reason,
    ) {
    }

    public static function fromEgress(array $data): self
    {
        return new self(
            (bool) ($data['ok'] ?? false),
            (bool) ($data['blocked'] ?? false),
            (string) ($data['method'] ?? 'GET'),
            (int) ($data['status'] ?? 0),
            (string) ($data['body'] ?? ''),
            (string) ($data['target'] ?? ''),
            (string) ($data['finalUrl'] ?? ''),
            isset($data['resolvedIp']) ? (string) $data['resolvedIp'] : null,
            (int) ($data['durationMs'] ?? 0),
            (string) ($data['error'] ?? ''),
            (string) ($data['reason'] ?? ''),
        );
    }

    public function withBody(string $body): self
    {
        return new self(
            $this->ok,
            $this->blocked,
            $this->method,
            $this->status,
            $body,
            $this->target,
            $this->finalUrl,
            $this->resolvedIp,
            $this->durationMs,
            $this->error,
            $this->reason,
        );
    }

    public function toArray(): array
    {
        return [
            'ok' => $this->ok,
            'blocked' => $this->blocked,
            'method' => $this->method,
            'status' => $this->status,
            'body' => $this->body,
            'target' => $this->target,
            'finalUrl' => $this->finalUrl,
            'resolvedIp' => $this->resolvedIp,
            'durationMs' => $this->durationMs,
            'error' => $this->error,
            'reason' => $this->reason,
        ];
    }
}
