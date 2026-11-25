<div align="center">

# WireArc

**轻量自托管的多协议节点中枢与 WireGuard 双机专线控制台**

[![CI](https://github.com/aoomee/wirearc/actions/workflows/checks.yml/badge.svg)](https://github.com/aoomee/wirearc/actions/workflows/checks.yml)
[![Release](https://img.shields.io/github/v/release/aoomee/wirearc?display_name=tag&color=007aff)](https://github.com/aoomee/wirearc/releases/latest)
[![GHCR](https://img.shields.io/badge/GHCR-aoomee%2Fwirearc-1d1d1f?logo=docker)](https://github.com/aoomee/wirearc/pkgs/container/wirearc)
[![Arch](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-34c759)](#docker-部署)

[核心特性](#核心特性) · [Docker 部署](#docker-部署) · [访问与反代](#访问与反代) · [双机中转](#wireguard-双机中转) · [运维与构建](#运维与构建) · [文档](#文档)

</div>

---

## 核心特性

- **双模 WireGuard 跨机专线** — 支持 **Agent 零配置直管**（自动分配隧道密钥与私网网段、链路异常阻断防直连泄漏）与 **SSH 独立自动化部署**（一键完成双端安装、端到端校验与回滚）。
- **全协议统一编排** — 基于 Sing-box 可视化管理 Reality、Hysteria2、TUIC、Shadowsocks、Trojan、VMess / VLESS 多传输层及 Socks5 等 17 种协议。
- **多端订阅与规则引擎** — 统一输出 Clash (Mihomo)、Sing-box、Surge 与通用 V2Ray 订阅；支持外部机场订阅聚合、内核级延迟与下载测速、自定义分流规则热编辑。
- **实时遥测与自动化运维** — WebSocket 秒级速率图表、日/月流量日历、配额达标自动熔断，集成 Cloudflare 证书 / Tunnel / 优选 IP 与 Telegram Bot 告警。

---

## Docker 部署

官方镜像 `ghcr.io/aoomee/wirearc:latest` 原生支持 `linux/amd64` 与 `linux/arm64`，所有配置、数据库与日志统一持久化在 `/app/data`。

### Docker Compose（推荐）

在服务器终端执行：

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

首次启动会自动创建管理员账号 **`admin`** 并生成高强度随机密码（不会输出到容器日志）。在宿主机查看初始密码：

```bash
# Docker Compose
docker compose exec wirearc cat /app/data/initial-admin-password

# Docker Run
docker exec wirearc cat /app/data/initial-admin-password
```

> 登录后修改密码会自动清理初始密码文件。自动化部署可在首次创建容器时传入环境变量 `NODECTL_INITIAL_ADMIN_PASSWORD`（12–72 字符）。

---

## 访问与反代

面板默认仅监听本机回环地址 `127.0.0.1:7878`，不向公网暴露未加密端口。

- **SSH 本地端口转发（免域名快速访问）**
  ```bash
  ssh -L 7878:127.0.0.1:7878 root@<服务器公网IP>
  ```
  转发建立后在本地浏览器打开 `http://127.0.0.1:7878`。
- **HTTPS 反向代理（生产环境 / 公网 Agent 接入）**
  使用 NGINX 或 Caddy 反代至 `http://127.0.0.1:7878`，保留 `Host`、开启 WebSocket `Upgrade` 并配置 `NODECTL_TRUSTED_PROXIES`。详见 [NGINX 反代配置指南](docs/reverse-proxy.md)。

---

## WireGuard 双机中转

| 模式 | 入口位置 | 链路拓扑 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **Agent 直管模式** | 节点编辑 → `REALITY` 卡片 → **出站方式** | `VLESS+REALITY (A) → WG → Shadowsocks (B)` | **日常主力推荐**。双端安装 Agent 后下拉即连，自动完成密钥分配、路由下发、健康巡检与故障阻断，计入实时流量统计。 |
| **SSH 独立模式** | 控制台首页 → **WG 中转** | `Realm / VLESS (A) → WG → REALITY / SS (B)` | **无 Agent 独立部署**。经 SSH 在双端部署独立 systemd 隧道与转发服务，业务校验通过后一键导入订阅。 |

---

## 运维与构建

```bash
# 平滑升级（保留全部节点与历史数据）
cd /opt/wirearc && docker compose pull && docker compose up -d

# 离线镜像加载（从 Releases 下载对应架构 .tar.gz）
docker load -i wirearc-v1.0.0-linux-amd64.tar.gz
NODECTL_IMAGE=ghcr.io/aoomee/wirearc:v1.0.0 docker compose up -d

# 本地源码构建
git clone https://github.com/aoomee/wirearc.git && cd wirearc
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

---

## 文档

- [NGINX HTTPS 反向代理配置](docs/reverse-proxy.md)
- [Agent 托管 WireGuard 专线架构](docs/wg-agent.md)
- [SSH 独立 WireGuard 中转说明](docs/wg-ssh.md)
- [开源致谢与组件说明](docs/credits.md)
