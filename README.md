<div align="center">

# WireArc

**轻量自托管的多协议节点中枢与 WireGuard 双机专线控制台**

[![CI](https://github.com/aoomee/wirearc/actions/workflows/checks.yml/badge.svg)](https://github.com/aoomee/wirearc/actions/workflows/checks.yml)
[![Release](https://img.shields.io/github/v/release/aoomee/wirearc?display_name=tag&color=007aff)](https://github.com/aoomee/wirearc/releases/latest)
[![GHCR](https://img.shields.io/badge/GHCR-aoomee%2Fwirearc-1d1d1f?logo=docker)](https://github.com/aoomee/wirearc/pkgs/container/wirearc)
[![Arch](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-34c759)](#docker-部署)

[核心特性](#核心特性) · [Docker 部署](#docker-部署) · [访问与反代](#访问与反代) · [双机专线](#wireguard-双机专线) · [运维与构建](#运维与构建) · [文档](#文档)

</div>

---

## 核心特性

- **纯 Go 轻量架构** — 零 Python 依赖、基于 Alpine 构建的超小多架构镜像，单一二进制即可运行。
- **Agent 托管 WireGuard 双机专线** — 无需 SSH 密码或手动授权，双端安装 Agent 后即可一键建立 `VLESS+REALITY → WireGuard → Shadowsocks` 加密中转，自动分配隧道密钥与网段，异常自动阻断防泄漏。
- **17 种协议统一编排** — 基于 Sing-box 可视化管理 Reality、Hysteria2、TUIC、Shadowsocks、Trojan、VMess / VLESS 多传输层与 Socks5。
- **多端订阅与实时遥测** — 统一输出 Clash (Mihomo)、Sing-box、Surge 与 V2Ray 订阅；内置机场聚合测速、WebSocket 秒级速率图表、流量配额熔断、Cloudflare 证书/Tunnel/优选 IP 与 Telegram Bot 告警。

---

## Docker 部署

官方镜像 `ghcr.io/aoomee/wirearc:latest` 原生支持 `linux/amd64` 与 `linux/arm64`，所有配置、数据库与日志持久化在 `/app/data`。

### Docker Compose（推荐）

```bash
mkdir -p /opt/wirearc && cd /opt/wirearc
curl -fsSL https://raw.githubusercontent.com/aoomee/wirearc/main/compose.yaml -o compose.yaml
docker compose up -d
```

若使用 1Panel、Portainer 或 Dockge 等容器面板，可直接粘贴以下 `compose.yaml`：

```yaml
services:
  wirearc:
    image: ghcr.io/aoomee/wirearc:latest
    container_name: wirearc
    restart: unless-stopped
    init: true
    environment:
      NODECTL_INITIAL_ADMIN_PASSWORD: ""
      NODECTL_TRUSTED_PROXIES: ""
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

### Docker Run

```bash
mkdir -p /opt/wirearc/data

docker run -d \
  --name wirearc \
  --restart unless-stopped \
  --init \
  --stop-timeout 75 \
  -p 127.0.0.1:7878:8080 \
  -v /opt/wirearc/data:/app/data \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  ghcr.io/aoomee/wirearc:latest
```

### 首次登录

首次启动会自动创建管理员账号 **`admin`** 与随机高强度密码（不会打印到日志），在宿主机执行以下命令查看：

```bash
docker exec $(docker ps --format '{{.Names}}' | grep -i wirearc | head -n1) cat /app/data/initial-admin-password
```

> 登录后修改密码会自动清理初始密码文件。自动化部署可在首次启动时传入 `NODECTL_INITIAL_ADMIN_PASSWORD`（12–72 字符）。

---

## 访问与反代

面板默认仅绑定宿主机回环地址 `127.0.0.1:7878`：

- **本地 SSH 转发**：`ssh -L 7878:127.0.0.1:7878 root@<服务器IP>`，浏览器访问 `http://127.0.0.1:7878`。
- **HTTPS 反向代理**：使用 NGINX / Caddy / 1Panel 将 HTTPS 域名反代至 `http://127.0.0.1:7878`，保留 `Host`、开启 WebSocket `Upgrade` 并配置 `NODECTL_TRUSTED_PROXIES`（或在面板「系统设置」中放行内网回源）。详见 [NGINX 反代配置指南](docs/reverse-proxy.md)。

---

## WireGuard 双机专线

1. 在**落地节点 B**（分组设为「落地」）启用 `SS` 并推送配置。
2. 在**入口节点 A**（分组设为「直连」）启用 `REALITY` 并推送配置。
3. 在入口节点 A 的 `REALITY` 协议卡片中将出站切换为 **经 WG → SS 出站**，选择落地节点 B 并点击 **推送配置** 即可自动完成双端隧道部署与巡检。

---

## 运维与构建

```bash
# 平滑升级
cd /opt/wirearc && docker compose pull && docker compose up -d

# 离线镜像加载
docker load -i wirearc-v1.1.0-linux-amd64.tar.gz
NODECTL_IMAGE=ghcr.io/aoomee/wirearc:v1.1.0 docker compose up -d

# 本地源码构建
git clone https://github.com/aoomee/wirearc.git && cd wirearc
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

---

## 文档

- [NGINX HTTPS 反向代理配置](docs/reverse-proxy.md)
- [Agent 托管 WireGuard 专线架构](docs/wg-agent.md)
- [开源致谢与组件说明](docs/credits.md)
