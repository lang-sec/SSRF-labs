<?php

declare(strict_types=1);

namespace SsrfLab\Support;

final class HttpClient
{
    public function __construct(private readonly int $level)
    {
    }

    public function get(string $url, array $options = []): HttpResponse
    {
        return HttpResponse::fromEgress(\lab_egress_http($this->level, $url, $options));
    }

    public function getWithoutBody(string $url, array $options = []): HttpResponse
    {
        $options['returnBody'] = false;

        return $this->get($url, $options);
    }

    public function gopher(string $url): HttpResponse
    {
        return HttpResponse::fromEgress(\lab_egress_gopher($this->level, $url));
    }

    public function readFile(string $url): HttpResponse
    {
        return HttpResponse::fromEgress(\lab_egress_read_file($this->level, $url));
    }
}
