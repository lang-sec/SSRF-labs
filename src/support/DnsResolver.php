<?php

declare(strict_types=1);

namespace SsrfLab\Support;

/**
 * 实验环境的确定性 DNS 解析器。
 *
 * 重绑定、混合记录和云元数据域名都由这里确定性返回；每个请求实例化一次，
 * 避免 PHP 内置服务器跨请求复用查询次数。
 */
final class DnsResolver
{
    private int $rebindLookups = 0;

    /**
     * @return string[] 解析到的 A 记录。
     */
    public function lookup(string $host): array
    {
        $host = lab_host_without_brackets($host);
        if ($host === '') {
            return [];
        }

        if (rtrim($host, '.') === 'localhost') {
            return ['127.0.0.1'];
        }

        if (lab_is_rebind_host($host)) {
            $this->rebindLookups++;

            // 第一次返回公网地址用于业务校验，第二次返回回环地址用于真实连接。
            return $this->rebindLookups === 1 ? ['203.0.113.77'] : ['127.0.0.1'];
        }

        if (lab_is_dual_dns_host($host)) {
            return ['203.0.113.88', '127.0.0.1'];
        }

        if (lab_is_cloud_metadata_host($host)) {
            return ['127.0.0.1'];
        }

        $normalized = lab_normalize_host($host);
        if ($normalized !== null && filter_var($normalized, FILTER_VALIDATE_IP) !== false) {
            return [$normalized];
        }

        return [];
    }

    public function lookupOne(string $host): ?string
    {
        $records = $this->lookup($host);

        return $records[0] ?? null;
    }

    /**
     * 连接阶段使用的地址：混合 DNS 场景取第二条记录，其余取第一条。
     */
    public function connectionIp(string $host): ?string
    {
        $records = $this->lookup($host);

        return $records[1] ?? $records[0] ?? null;
    }
}
