<?php

declare(strict_types=1);

/**
 * 所有入口都会先加载这里：
 * - challenges.php 提供关卡、代码和漏洞成因。
 * - functions.php 提供 URL 处理、请求执行和实验安全边界。
 * - LAB_ROLE 决定当前 PHP 进程是主站、内部服务还是回调服务。
 */
require_once __DIR__ . '/challenges.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/support/DnsResolver.php';
require_once __DIR__ . '/egress.php';
require_once __DIR__ . '/business_api.php';

if (!defined('LAB_ROLE')) {
    define('LAB_ROLE', getenv('LAB_ROLE') ?: 'app');
}

lab_base_headers();

