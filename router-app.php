<?php

declare(strict_types=1);

// 主站路由：静态资源交给 PHP 内置服务器，其余请求进入 public/index.php。
define('LAB_ROLE', 'app');

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$candidate = __DIR__ . DIRECTORY_SEPARATOR . 'public' . str_replace('/', DIRECTORY_SEPARATOR, $path);

if ($path !== '/' && is_file($candidate)) {
    return false;
}

require __DIR__ . '/public/index.php';

