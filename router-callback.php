<?php

declare(strict_types=1);

// 盲回调、渲染页面和恶意 RSS 服务，只在 127.0.0.1:8084 启动。
define('LAB_ROLE', 'callback');
require __DIR__ . '/public/index.php';

