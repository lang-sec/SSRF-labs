<?php

declare(strict_types=1);

namespace SsrfLab\Support;

final class NetworkGuard
{
    public function normalizeHost(string $host): ?string
    {
        return \lab_normalize_host($host);
    }

    public function isPrivateIp(string $ip): bool
    {
        return \lab_is_private_ip($ip);
    }

    public function isLoopbackHost(string $host): bool
    {
        return \lab_is_loopback_ip($this->normalizeHost($host) ?? '');
    }

    public function isRebindHost(string $host): bool
    {
        return \lab_is_rebind_host($host);
    }

    public function isDualDnsHost(string $host): bool
    {
        return \lab_is_dual_dns_host($host);
    }

    public function isCloudMetadataHost(string $host): bool
    {
        return \lab_is_cloud_metadata_host($host);
    }
}
