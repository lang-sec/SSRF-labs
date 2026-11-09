# SSRF Field Lab

一个 PHP SSRF 教学靶场。默认运行在本机回环地址；第 1/12 关使用独立的 `10.220.2.6:8080` 验证主机（由 Docker 内网模拟，非真实生产主机）。课程覆盖有回显/无回显验证、URL 解析、地址编码、DNS、重定向、Header、协议跳板、云元数据、渲染器和业务导入等 16 个场景。

每个关卡都是一个独立的真实业务接口（例如 `POST /products/import-image`），接口内部实现自己的、故意有缺陷的校验和请求逻辑。前端是简单的关卡页：只显示目标输入、结果/FLAG、三级提示和通关后可查看的源码，不展示业务背景。`/api/probe` 模拟入口已经退役。

## 快速开始

推荐使用 Docker 运行完整环境（包含第 1/12 关的验证主机）：

```bash
docker compose up -d --build
```

打开：

```text
http://127.0.0.1:8080
```

停止：

```bash
docker compose down
```

本地 Windows 开发环境：

- Windows PowerShell
- PHP 8.1+，需要启用 `curl` 扩展
- 运行 `.\start.ps1` 启动，`.\stop.ps1` 停止
- 本地只启动 127.0.0.1 上的教学服务；第 1/12 关的验证主机在 Docker 中，本地运行这两关会显示目标不可达，冒烟测试会自动跳过

### 测试

```bash
# Docker 内完整 16 关
docker exec ssrf-lab php tests/smoke.php

# 本地 Windows（自动跳过不可达的第 1/12 关）
.\tests\smoke.ps1
php tests/smoke.php

# 浏览器界面测试（本地）
node tests/browser-smoke.js
```

## 关卡目录

| 关卡 | 绕过方式 | 核心问题 |
| --- | --- | --- |
| 1 | 有回显 SSRF 验证 | 验证端点根路径返回 MD5 |
| 2 | 黑名单变形 | 只对常见回环字符串做黑名单 |
| 3 | 关键词白名单 | 在完整 URL 中搜索域名而不是校验 Host |
| 4 | 重定向绕过 | 只检查首跳并自动跟随 Location |
| 5 | DNS 重绑定 | 校验解析与实际连接解析不一致 |
| 6 | 协议走私 | 黑名单遗漏 `file://` |
| 7 | URL 解析差异 | 把 userinfo 当成了真实 Host |
| 8 | 特殊 IP 编码 | 八进制、缩写和 IPv4 映射 IPv6 |
| 9 | 混合 DNS 记录 | 只检查第一条 A 记录 |
| 10 | 多级重定向 | 中间跳合法，最后一跳进入内网 |
| 11 | Header 驱动 SSRF | `X-Forwarded-Host` 被直接拼入目标地址 |
| 12 | 无回显 SSRF 验证 | `/index?host=dnslog` 触发真实 DNS 查询 |
| 13 | Gopher 协议跳板 | HTTP 客户端变成通用 TCP 客户端 |
| 14 | 云元数据变体 | 只拦截一个元数据 IP，遗漏云厂商域名 |
| 15 | 渲染器 SSRF | HTML 子资源触发第二次未校验请求 |
| 16 | RSS 导入 SSRF | 订阅内容中的 enclosure 被自动抓取 |

每关包含：

- 一个真实业务接口（界面不展示业务细节）
- 服务端目标 URL 输入和原始响应
- 命中后的 FLAG / MD5 / DNS 证据展示
- 三级渐进提示
- 通关后可查看本关 PHP 源码

每个关卡对应一个独立的业务控制器文件 `src/levels/*Controller.php`，漏洞逻辑就在该文件中；通关后展示的是这个文件的实际源码，而不是额外的演示片段。共享的出网网关、HTTP 客户端、DNS 解析器和网络判断位于 `src/support/`。

初始 `/api/bootstrap` 只返回标题、提示、表单字段和业务路由，不下发 `successFlag`、业务描述或源码；目标地址放在提示里，由学习者逐条查看。源码只在通关响应中返回，并保存在当前浏览器；重置进度后清除。

## 验证端点（第 1/12 关）

| 场景 | 提交地址 | 判定 |
| --- | --- | --- |
| 有回显 SSRF | `http://10.220.2.6:8080/` | 响应包含 32 位十六进制 MD5 |
| 无回显 SSRF（dnslog） | `http://10.220.2.6:8080/index?host=<dnslog 子域名>` | 目标发起真实 DNS A 查询，dnslog 平台收到记录 |
| 内网访问模拟 | `http://10.220.2.6:8080/index?host=ssrf-lab&port=8081&path=/admin` | 目标访问靶场内部服务，界面只显示 HTTP 状态和字节数 |

说明：

- `10.220.2.6:8080` 由 `ssrf-target` 容器在 Docker `labnet` 网络中提供，不是宿主机回环地址，也不发布到宿主机。
- target 容器的 DNS 查询是真实出网的；dnslog 使用 ceye.io、dnslog.cn 等外部平台。
- 内网访问只允许 `ssrf-lab` 的 8081–8084，避免 target 变成任意内网扫描器；响应正文不会回显给学习者。
- 如果 `10.220.2.0/24` 与现有网络冲突，修改 `docker-compose.yml` 的 `labnet` 子网和 target IP，并同步 `src/functions.php` 中的 `LAB_TARGET_HOST` / `LAB_TARGET_PORT`。

## 真实业务接口

前端和冒烟测试直接调用这些端点（界面不展示业务描述），请求体为 JSON：

| 关卡 | 业务接口 | 参数 | 说明 |
| --- | --- | --- | --- |
| 1 | `POST /products/import-image` | `image_url` | 有回显 SSRF 验证（目标返回 MD5） |
| 2 | `POST /merchants/import-logo` | `logo_url` | 品牌 Logo 自动抓取 |
| 3 | `POST /campaigns/check-asset` | `asset_url` | 营销素材检查 |
| 4 | `POST /messages/link-preview` | `preview_url` | 站外链接预览 |
| 5 | `POST /profiles/avatar-preview` | `avatar_url` | CDN 头像预览 |
| 6 | `POST /knowledge-base/preview-attachment` | `attachment_url` | 知识库附件预览 |
| 7 | `POST /profiles/sync-avatar` | `avatar_url` | 社交头像同步 |
| 8 | `POST /admin/assets/migrate` | `asset_url` | 静态资源迁移 |
| 9 | `POST /partners/media-sync` | `media_url` | 合作伙伴媒体同步 |
| 10 | `POST /messages/rich-preview` | `preview_url` | 聊天链接预览 |
| 11 | `POST /webhook/test` | `base_url` + `X-Forwarded-Host` 请求头 | Webhook 连通性测试 |
| 12 | `POST /reports/export` | `callback_url` | 无回显 SSRF 验证（`/index?host=dnslog`） |
| 13 | `POST /marketing/collect-asset` | `resource_url` | 运营素材采集器 |
| 14 | `POST /cloud/import-asset` | `asset_url` | 云存储资源导入 |
| 15 | `POST /sharing/card` | `page_url` | 分享链接卡片生成 |
| 16 | `POST /feeds/import` | `feed_url` | 合作伙伴 RSS 导入 |

第 11 关的代理头由浏览器真实发送；其余关卡的验证地址、提示和源码通过界面和通关响应提供。

## 靶场服务

```text
127.0.0.1:8080  app       主界面、16 个真实业务接口和 /api/* 辅助接口
127.0.0.1:8081  internal  模拟内部管理、调试和业务目标
127.0.0.1:8082  metadata  模拟 AWS/GCP 云元数据
127.0.0.1:8083  redirect  模拟公开单级和多级重定向
127.0.0.1:8084  callback  模拟回调、渲染页面和恶意 RSS
127.0.0.1:6380  gopher    模拟内部非 HTTP TCP 服务
10.220.2.6:8080 target    模拟外部验证主机（Docker 独立容器，不发布到宿主机）
```

本地 Windows 运行时，8081–8084 和 6380 监听 `127.0.0.1`。Docker 部署时，8081–8084 在容器网络内监听（不发布到宿主机），供 app 自身和 target 容器模拟内网访问；只有 app 的 8080 发布。

所有业务 handler 的出网请求统一经过 `src/egress.php` 的实验网关：

- 默认只允许本机回环地址和教学用内部域名
- 第 1/12 关额外允许 `10.220.2.6:8080` 这个验证端点
- 只允许端口 `8080` 到 `8084`
- gopher 只允许访问 `127.0.0.1:6380`
- `file://` 只允许读取 `secrets/level6.txt`
- 业务出网不允许访问公网 HTTP 和系统代理；target 容器的 DNS 查询是真实出网，用于 dnslog 验证

业务层的弱校验（故意可绕过）与实验边界（不可突破）是分开的：关卡可以绕过业务校验，但不能突破实验环境的网络限制。第 5/9/14 关的 DNS 解析由 `src/dns.php` 的确定性实验室解析器提供，每个请求重新实例化。

## 主要文件

- `src/levels/*Controller.php` — 每关一个真实业务控制器，漏洞逻辑和通关后展示的源码都在这里
- `src/business_api.php` — 控制器路由、结果信封、日志和源码下发
- `src/support/HttpClient.php` — 业务共享 HTTP 客户端
- `src/support/NetworkGuard.php` — 地址归一化和网络判断
- `src/support/DnsResolver.php` — 第 5/9/14 关的确定性 DNS 解析器
- `src/support/BusinessController.php` — 控制器基类（输入、Header、拒绝、响应）
- `src/egress.php` — 出网边界网关、协议、重定向复查
- `src/challenges.php` / `src/advanced_challenges.php` — 关卡、提示和判定配置
- `public/index.php` — app、internal、metadata、redirect、callback、target 角色分发
- `router-target.php` — `10.220.2.6:8080` 验证主机入口
- `docker-compose.yml` — `ssrf-lab` 与 `ssrf-target` 两个容器

## 重要说明

- 这是故意脆弱的本地教学程序，不要部署到公网。
- 模拟元数据、Redis、回调、内部服务以及 `10.220.2.6:8080` 验证主机都不连接真实生产环境。
- `10.220.2.6` 是靶场 Docker 网络中的模拟地址，不是真实生产主机；如果要指向真实验证端点，需要修改 target 配置和实验边界。
- 第 1/12 关的 dnslog 解析由独立的 target 容器发起，学习者在 ceye.io/dnslog.cn 等外部平台查看记录。
- FLAG / MD5 / DNS 证据只用于判定学习进度，不具备真实凭据价值。
- 服务端请求日志保存在 `storage/requests.jsonl`。

## Docker 部署

```bash
docker compose up -d --build
```

- 启动 `ssrf-lab` 和 `ssrf-target` 两个容器；`ssrf-target` 通过 `labnet` 网络获得 `10.220.2.6`，模拟外部验证主机。
- 仅发布 `8080`（主界面）；8081–8084 只在容器网络内监听，不发布到宿主机；6380 仍为回环。
- `target` 的 `/` 返回 MD5；`/index?host=<dnslog>` 发起真实 DNS 查询；`/index?host=ssrf-lab&port=8081&path=/admin` 模拟目标访问内部服务。
- 查看状态：`docker compose ps`（应看到 `ssrf-lab` 和 `ssrf-target` 均为 healthy）；查看日志：`docker compose logs -f`；停止并删除容器：`docker compose down`。
- 容器内运行 16 关冒烟测试：`docker exec ssrf-lab php tests/smoke.php`。
- 仍然只适合本地或实验网络使用，不要暴露到公网。
