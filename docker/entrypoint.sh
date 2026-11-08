#!/usr/bin/env bash
set -euo pipefail

cd /opt/ssrf-lab

pids=()

cleanup() {
    trap - TERM INT EXIT
    for pid in "${pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup TERM INT EXIT

start() {
    "$@" &
    pids+=("$!")
}

# 主应用对外监听；内部服务在容器网络内监听，供 app 自身和目标容器模拟内网访问。
start php -S 0.0.0.0:8080 -t public router-app.php
start php -S 0.0.0.0:8081 -t public router-internal.php
start php -S 0.0.0.0:8082 -t public router-metadata.php
start php -S 0.0.0.0:8083 -t public router-redirect.php
start php -S 0.0.0.0:8084 -t public router-callback.php
start php bin/mock-tcp.php

echo "SSRF Field Lab: app 0.0.0.0:8080, internal 0.0.0.0:8081-8084 (container network), gopher 127.0.0.1:6380"

status=0
wait -n || status=$?
echo "A lab service exited (status ${status}); stopping the container." >&2
exit "$status"
