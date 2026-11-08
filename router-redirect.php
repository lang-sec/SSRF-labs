<?php

declare(strict_types=1);

// 公开重定向服务，只在 127.0.0.1:8083 启动。
define('LAB_ROLE', 'redirect');
require __DIR__ . '/public/index.php';

