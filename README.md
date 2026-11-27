<div align="center">

<img src="docs/assets/logo.svg" width="84" height="84" alt="WireArc" />

# WireArc

**轻量自托管的多协议节点中枢与 WireGuard 双机专线控制台**

[![CI](https://github.com/aoomee/wirearc/actions/workflows/checks.yml/badge.svg)](https://github.com/aoomee/wirearc/actions/workflows/checks.yml)
[![Release](https://img.shields.io/github/v/release/aoomee/wirearc?display_name=tag&color=007aff)](https://github.com/aoomee/wirearc/releases/latest)
[![GHCR](https://img.shields.io/badge/GHCR-aoomee%2Fwirearc-1d1d1f?logo=docker)](https://github.com/aoomee/wirearc/pkgs/container/wirearc)
[![Arch](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-34c759)](#快速部署)

[核心特性](#核心特性) · [快速部署](#快速部署) · [反向代理](#反向代理与访问) · [双机专线](#节点接入与-wireguard-双机专线) · [运维构建](#常用运维与构建) · [文档](#文档)

</div>

---

## 核心特性

| 模块 | 说明 |
| :--- | :--- |
| **纯 Go 轻量架构** | 基于 Alpine 构建的多架构极简容器镜像（`amd64` / `arm64`），零 Python 依赖，单一二进制运行，支持 SQLite 与 PostgreSQL，首屏服务端直出零瀑布加载。 |
| **WireGuard 双机专线** | 无需 SSH 密码，双端安装受管 Agent 即可一键编排 `VLESS+REALITY → WireGuard → Shadowsocks` 加密转发，自动分配密钥与网段，具备 fail-closed 异常阻断与配对态免静默重启保护。 |
| **17 种协议与多端订阅** | 基于 Sing-box 统一管理 Reality、Hysteria2、TUIC、Shadowsocks、Trojan、VMess / VLESS 多传输层与 Socks5；一键输出 Clash (Mihomo)、Sing-box、Surge 与 V2Ray 订阅，支持机场聚合测速。 |
| **实时遥测与运维工具** | WebSocket 2 秒级流量与速率监控、网卡自愈、地区旗帜手动覆写、流量限额熔断、日志详情排查，以及内置 Cloudflare 证书 / Tunnel / 优选 IP 与 Telegram Bot 告警。 |

---

## 快速部署

官方镜像 `ghcr.io/aoomee/wirearc:latest` 原生支持 `linux/amd64` 与 `linux/arm64`，所有数据库、证书与日志均持久化在 `/app/data`。

### Docker Compose（推荐，通用配置）

适用于 **1Panel、Portainer、Dockge** 或任意 Linux 服务器，直接复制保存为 `compose.yaml`：

```yaml
services:
  wirearc:
    image: ghcr.io/aoomee/wirearc:latest
    restart: unless-stopped
    init: true
    environment:
      WIREARC_INITIAL_ADMIN_PASSWORD: ""
      WIREARC_TRUSTED_PROXIES: "127.0.0.1/32,172.16.0.0/12"
    ports:
      - "127.0.0.1:7878:8080"
    volumes:
      - ./data:/app/data
    stop_grace_period: 75s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

在宿主机命令行启动（或直接在容器面板中创建编排启动）：

```bash
docker compose up -d
```

> **端口说明**：默认仅绑定回环地址 `127.0.0.1:7878`，推荐配合 HTTPS 反向代理访问；如需通过服务器公网 `IP:7878` 直连，将 `ports` 改为 `- "7878:8080"` 并在防火墙放行对应端口。

<details>
<summary>使用命令行直接拉取仓库 compose.yaml 或 Docker Run 启动</summary>

**方式 A：拉取仓库编排文件**

```bash
mkdir -p /opt/wirearc && cd /opt/wirearc
curl -fsSL https://raw.githubusercontent.com/aoomee/wirearc/main/compose.yaml -o compose.yaml
docker compose up -d
```

**方式 B：Docker Run**

```bash
mkdir -p /opt/wirearc/data

docker run -d \
  --name wirearc \
  --restart unless-stopped \
  --init \
  --stop-timeout 75 \
  -e WIREARC_TRUSTED_PROXIES="127.0.0.1/32,172.16.0.0/12" \
  -p 127.0.0.1:7878:8080 \
  -v /opt/wirearc/data:/app/data \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  ghcr.io/aoomee/wirearc:latest
```

</details>

### 环境变量

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `WIREARC_INITIAL_ADMIN_PASSWORD` | 留空（自动生成） | 首次初始化管理员账号 `admin` 的密码（12–72 字符）；已有数据库时自动忽略。 |
| `WIREARC_TRUSTED_PROXIES` | 留空 | 反向代理的 TCP 来源 IP / CIDR（逗号分隔），用于识别真实客户端 IP、防限流误封及开启 Secure Cookie。 |
| `TZ` | `Asia/Shanghai` | 容器时区（影响日志时间与流量重置周期）。 |

### 首次登录

首次启动且未指定初始密码时，系统会自动创建管理员账号 **`admin`** 并将强随机密码写入 `./data/initial-admin-password`（权限 `0600`，不会输出到容器日志）：

```bash
cat ./data/initial-admin-password
```

> 登录后在面板修改密码会自动清理初始密码文件。

---

## 反向代理与访问

- **SSH 本地端口转发（免暴露端口）**：执行 `ssh -L 7878:127.0.0.1:7878 root@<服务器IP>`，浏览器访问 `http://127.0.0.1:7878`。
- **HTTPS 反向代理（NGINX / OpenResty / 1Panel / Caddy）**：转发至 `http://127.0.0.1:7878`，务必开启 WebSocket 升级头并关闭响应缓冲（保证节点 Agent 实时通道与 SSE 更新日志流畅）：

```nginx
location ^~ / {
    proxy_pass http://127.0.0.1:7878;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    proxy_buffering off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

完整配置与安全边界说明见 [NGINX HTTPS 反向代理配置指南](docs/reverse-proxy.md)。

---

## 节点接入与 WireGuard 双机专线

1. **接入节点**：在面板「系统设置」填好面板公网地址，点击「新增节点」复制一键安装命令到 VPS 执行即可。安装后服务名为 `wirearc-agent.service`，支持使用 `wa` 快捷管理命令。
2. **配置落地节点 B**：将节点分组设为「落地」，启用 `Shadowsocks` 协议并推送配置。
3. **配置入口节点 A**：将节点分组设为「直连」，启用 `REALITY` 协议并推送配置。
4. **一键打通专线**：在入口节点 A 的 `REALITY` 卡片中将出站模式切换为 **经 WG → SS 出站**，选择落地节点 B 并点击 **推送配置**，双端将自动完成内核 WireGuard 隧道建链与健康巡检。

---

## 常用运维与构建

```bash
# 平滑升级到最新版
docker compose pull && docker compose up -d

# 离线镜像导入（从 Release 下载对应架构压缩包）
docker load -i wirearc-v1.0.0-linux-amd64.tar.gz
docker compose up -d

# 本地源码构建
git clone https://github.com/aoomee/wirearc.git && cd wirearc
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

---

## 文档

- [NGINX HTTPS 反向代理配置](docs/reverse-proxy.md)
- [Agent 托管 WireGuard 专线架构](docs/wg-agent.md)
- [开源致谢与组件说明](docs/credits.md)
