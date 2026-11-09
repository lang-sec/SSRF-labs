<?php

declare(strict_types=1);

require_once __DIR__ . '/levels/registry.php';

/**
 * 业务接口路由器。
 *
 * 每个关卡的真实业务逻辑都在 src/levels/*Controller.php 中；
 * 这里只负责选择控制器、统一结果信封、日志和"通关后下发源码"。
 */

function lab_business_routes(): array
{
    static $routes = null;
    if ($routes !== null) {
        return $routes;
    }

    $handlers = lab_level_handlers();
    $routes = [];

    foreach (lab_business_scenarios() as $level => $scenario) {
        $path = (string) ($scenario['api'] ?? '');
        $level = (int) $level;
        $handler = $handlers[$level] ?? null;
        if ($path === '' || $handler === null) {
            continue;
        }

        $routes[$path] = [
            'path' => $path,
            'level' => $level,
            'method' => strtoupper((string) ($scenario['method'] ?? 'POST')),
            'param' => (string) ($scenario['param'] ?? 'url'),
            'handler' => (string) $handler['class'],
            'action' => (string) $handler['action'],
            'source' => (string) $handler['source'],
        ];
    }

    return $routes;
}

function lab_business_route(string $path): ?array
{
    return lab_business_routes()[$path] ?? null;
}

function lab_business_input(): array
{
    static $input = null;
    if ($input !== null) {
        return $input;
    }

    // 同时支持 JSON body、表单编码和查询参数；JSON 优先。
    $input = array_merge($_GET, $_POST, lab_read_json_body());

    return $input;
}

function lab_business_blocked(int $started, string $message, string $target): array
{
    $result = lab_result_error($message, $started, 'blocked');
    $result['transport']['target'] = $target;

    return $result;
}

function lab_business_envelope(array $challenge, array $fetch, string $allowedMessage, ?bool $solved = null): array
{
    $blocked = (bool) ($fetch['blocked'] ?? false);
    $ok = !$blocked && (bool) ($fetch['ok'] ?? false);
    $body = (string) ($fetch['body'] ?? '');

    $message = match (true) {
        $blocked => (string) ($fetch['reason'] ?? '实验边界拦截。'),
        $ok => $allowedMessage,
        default => (string) (($fetch['error'] ?? '') !== '' ? $fetch['error'] : '请求失败。'),
    };

    return [
        'ok' => $ok,
        'blocked' => $blocked,
        'validation' => [
            'decision' => $blocked ? 'blocked' : ($ok ? 'allowed' : 'error'),
            'message' => $message,
        ],
        'transport' => [
            'method' => (string) ($fetch['method'] ?? 'GET'),
            'target' => (string) ($fetch['target'] ?? ''),
            'finalUrl' => (string) ($fetch['finalUrl'] ?? ''),
            'resolvedIp' => $fetch['resolvedIp'] ?? null,
        ],
        'response' => [
            'status' => (int) ($fetch['status'] ?? 0),
            'durationMs' => (int) ($fetch['durationMs'] ?? 0),
            'bytes' => strlen($body),
            'body' => $body,
        ],
        'solved' => $solved ?? str_contains($body, (string) ($challenge['successFlag'] ?? '')),
    ];
}

function lab_business_outcome(array $challenge, array $outcome, int $started): array
{
    if (!empty($outcome['blocked'])) {
        return lab_business_blocked(
            $started,
            (string) ($outcome['message'] ?? '业务校验未通过。'),
            (string) ($outcome['logUrl'] ?? '')
        );
    }

    $response = $outcome['response'] ?? null;
    if (!$response instanceof \SsrfLab\Support\HttpResponse) {
        return lab_result_error('业务处理失败。', $started);
    }

    $solved = $outcome['solved'] ?? null;

    return lab_business_envelope(
        $challenge,
        $response->toArray(),
        (string) ($outcome['message'] ?? ''),
        is_bool($solved) ? $solved : null
    );
}

function lab_business_finish(
    int $level,
    array $challenge,
    string $logUrl,
    array $result,
    int $started,
    ?string $sourceFile = null
): never {
    lab_append_log([
        'level' => $level,
        'levelTitle' => (string) ($challenge['title'] ?? ''),
        'url' => $logUrl,
        'decision' => (string) ($result['validation']['decision'] ?? 'error'),
        'message' => (string) ($result['validation']['message'] ?? ''),
        'status' => (int) ($result['response']['status'] ?? 0),
        'durationMs' => (int) ($result['response']['durationMs'] ?? 0),
        'finalUrl' => (string) ($result['transport']['finalUrl'] ?? ''),
        'solved' => (bool) ($result['solved'] ?? false),
    ]);

    $payload = [
        'level' => $level,
        'result' => $result,
        'elapsedMs' => (int) round((hrtime(true) - $started) / 1_000_000),
    ];

    // 源码只随"已通关"的响应下发，初始 bootstrap 中不包含源码。
    // 展示内容直接读取该关的控制器文件，保证源码就是实际执行的业务代码。
    if (($result['solved'] ?? false) === true && $sourceFile !== null && is_file($sourceFile)) {
        $payload['source'] = [
            'codeLabel' => 'src/levels/' . basename($sourceFile),
            'snippet' => (string) file_get_contents($sourceFile),
        ];
    }

    lab_json_response($payload);
}

function lab_business_dispatch(string $path, string $method): never
{
    $route = lab_business_route($path);
    if ($route === null) {
        lab_json_response(['error' => 'Business endpoint not found'], 404);
    }

    if (strtoupper($method) !== $route['method']) {
        header('Allow: ' . $route['method']);
        lab_json_response(['error' => 'Method not allowed'], 405);
    }

    $challenges = lab_challenges();
    $level = (int) $route['level'];
    if (!isset($challenges[$level])) {
        lab_json_response(['error' => 'Unknown business route'], 404);
    }

    $handler = (string) $route['handler'];
    $action = (string) $route['action'];
    if (!class_exists($handler) || !method_exists($handler, $action)) {
        lab_json_response(['error' => 'Business handler unavailable'], 500);
    }

    $started = hrtime(true);

    try {
        $controller = new $handler($level, lab_business_input());
        $outcome = $controller->{$action}();
    } catch (\SsrfLab\Support\MissingInputException $exception) {
        lab_json_response(['error' => $exception->getMessage()], 422);
    } catch (\Throwable $exception) {
        lab_json_response(['error' => 'Business handler failed'], 500);
    }

    if (!is_array($outcome)) {
        lab_json_response(['error' => 'Business handler returned an invalid result'], 500);
    }

    $result = lab_business_outcome($challenges[$level], $outcome, $started);
    $logUrl = (string) ($outcome['logUrl'] ?? ($result['transport']['target'] ?? ''));

    lab_business_finish(
        $level,
        $challenges[$level],
        $logUrl,
        $result,
        $started,
        (string) ($route['source'] ?? '')
    );
}
