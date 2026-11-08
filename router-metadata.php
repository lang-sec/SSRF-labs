<?php

declare(strict_types=1);

// 模拟云元数据服务，只在 127.0.0.1:8082 启动。
define('LAB_ROLE', 'metadata');
require __DIR__ . '/public/index.php';

