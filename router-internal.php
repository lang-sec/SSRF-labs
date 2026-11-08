<?php

declare(strict_types=1);

// 内部服务路由：只在 127.0.0.1:8081 启动。
define('LAB_ROLE', 'internal');
require __DIR__ . '/public/index.php';

