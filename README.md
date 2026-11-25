<div align="center">

# WireArc

**轻量自托管的多协议节点中枢与 WireGuard 双机中转控制台**

[![Checks](https://github.com/aoomee/wirearc/actions/workflows/checks.yml/badge.svg)](https://github.com/aoomee/wirearc/actions/workflows/checks.yml)
[![Release](https://img.shields.io/github/v/release/aoomee/wirearc?display_name=tag&color=007aff)](https://github.com/aoomee/wirearc/releases/latest)
[![GHCR](https://img.shields.io/badge/GHCR-aoomee%2Fwirearc-1d1d1f?logo=docker)](https://github.com/aoomee/wirearc/pkgs/container/wirearc)
[![Arch](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-34c759)](#docker-部署)

[核心特性](#核心特性) · [Docker 部署](#docker-部署) · [访问与反代](#访问与反代) · [双机中转](#wireguard-双机中转) · [更新与构建](#更新与构建) · [进阶文档](#进阶文档)

</div>

---

## 核心特性

- **双模 WireGuard 跨机专线** — 支持 **Agent 零配置直管**（自动分配隧道密钥与私网 IP、故障阻断防直连泄漏）与 **SSH 独立自动化部署**（一键完成双端安装、联调校验与回滚）。
- **全协议统一编排** — 基于 Sing-box 可视化管理 Reality、Hysteria2、TUIC、Shadowsocks、Trojan、VMess / VLESS 多传输层及 Socks5 等 17 种协议。
- **多端订阅与规则引擎** — 统一输出 Clash (Mihomo)、Sing-box、Surge 与通用 V2Ray 订阅；支持外部机场订阅聚合、内核级延迟与下载测速、自定义分流规则在线热编辑。
- **实时遥测与自动化运维** — WebSocket 秒级速率图表、日/月流量历史日历、配额达标自动熔断，集成 Cloudflare 证书 / Tunnel / 优选 IP 与 Telegram Bot 告警。

---

## Docker 部署

官方镜像 `ghcr.io/aoomee/wirearc:latest` 原生支持 `linux/amd64` 与 `linux/arm64`，所有配置、数据库与日志统一持久化在 `/app/data`。

### 方式一：Docker Compose（推荐）

在服务器终端执行以下命令即可启动：

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

### 方式二：Docker Run

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

首次启动会自动创建管理员账号 **`admin`** 并生成高强度随机密码（不会输出到容器日志）。在宿主机执行以下命令查看初始密码：

```bash
# Docker Compose 部署
docker compose exec wirearc cat /app/data/initial-admin-password

# Docker Run 部署
docker exec wirearc cat /app/data/initial-admin-password
```

> 登录控制台并在右上角修改密码后，初始密码文件会自动销毁。自动化部署可在首次创建容器时设置环境变量 `NODECTL_INITIAL_ADMIN_PASSWORD`（12–72 字符）。

---

## 访问与反代

为保障安全，面板默认仅监听本机回环地址 `127.0.0.1:7878`，不向公网直接暴露未加密端口。

- **本地 SSH 隧道访问（免域名快速管理）**
  在本地电脑终端执行端口转发后，浏览器访问 `http://127.0.0.1:7878`：
  ```bash
  ssh -L 7878:127.0.0.1:7878 root@<服务器公网IP>
  ```
- **HTTPS 反向代理（生产环境 / 公网 Agent 接入推荐）**
  使用 NGINX / Caddy 将 HTTPS 域名反代至 `http://127.0.0.1:7878`，保留 `Host`、开启 WebSocket `Upgrade` 并在环境变量 `NODECTL_TRUSTED_PROXIES` 中填入反代来源 IP。完整配置示例见 [NGINX HTTPS 反代指南](REVERSE-PROXY.md)。

---

## WireGuard 双机中转

WireArc 同时提供两种跨机中转方案，按需选择：

| 模式 | 入口位置 | 链路拓扑 | 适用场景与特点 |
| :--- | :--- | :--- | :--- |
| **Agent 直管模式** | 节点编辑 → `REALITY` 卡片 → **出站方式** | `VLESS+REALITY (A) → WG → Shadowsocks (B)` | **日常主力推荐**。双端安装 Agent 后下拉即连，自动完成密钥交换、路由下发、健康巡检与异常阻断，纳入实时流量统计。 |
| **SSH 独立模式** | 控制台首页 → **WG 中转** | `Realm / VLESS (A) → WG → REALITY / SS (B)` | **无 Agent 纯净机器**。经 SSH 在双端部署独立 systemd 隧道与转发服务，端到端校验通过后一键导入自定义订阅。 |

---

## 更新与构建

**日常平滑升级**（保留全部节点、订阅与历史数据）：

```bash
cd /opt/wirearc
docker compose pull
docker compose up -d
```

**离线镜像部署**（从 [Releases](https://github.com/aoomee/wirearc/releases/latest) 下载对应架构 `.tar.gz`）：

```bash
docker load -i wirearc-v0.2.0-linux-amd64.tar.gz
NODECTL_IMAGE=ghcr.io/aoomee/wirearc:v0.2.0 docker compose up -d
```

**从源码本地构建**：

```bash
git clone https://github.com/aoomee/wirearc.git
cd wirearc
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

---

## 进阶文档

- [NGINX HTTPS 反向代理与可信代理配置](REVERSE-PROXY.md)
- [Agent 托管 WireGuard 专线架构说明](WG-AGENT-INTEGRATION.md)
- [SSH 独立 WireGuard 中转引擎说明](WG-README.md)
- [组件来源与开源致谢](WG-SOURCES.md) · 基于 [hobin66/nodectl](https://github.com/hobin66/nodectl) 演进开发
