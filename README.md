<div align="center">

<img src="docs/assets/logo.svg" width="84" height="84" alt="WireArc" />

# WireArc

**轻量自托管的多协议节点中枢与 WireGuard 双机专线控制台**

[![CI](https://github.com/aoomee/wirearc/actions/workflows/checks.yml/badge.svg)](https://github.com/aoomee/wirearc/actions/workflows/checks.yml)
[![Release](https://img.shields.io/github/v/release/aoomee/wirearc?display_name=tag&color=007aff)](https://github.com/aoomee/wirearc/releases/latest)
[![GHCR](https://img.shields.io/badge/GHCR-aoomee%2Fwirearc-1d1d1f?logo=docker)](https://github.com/aoomee/wirearc/pkgs/container/wirearc)
[![Arch](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-34c759)](#快速部署)

[特性](#核心特性) · [快速部署](#快速部署) · [反向代理](#反向代理) · [双机专线](#双机专线) · [运维](#运维与构建) · [文档](#文档)

</div>

---

## 核心特性

| 能力 | 说明 |
| :--- | :--- |
| **极简纯 Go 架构** | 多架构 Alpine 容器镜像（`amd64` / `arm64`），单二进制运行、零 Python 依赖、首屏直出零瀑布加载，支持 SQLite 与 PostgreSQL。 |
| **WireGuard 双机专线** | 免 SSH 密码，双端受管 Agent 一键建立 `VLESS+REALITY → WireGuard → Shadowsocks` 加密中转，自动分配密钥与网段，具备 fail-closed 异常阻断与配对态免静默重启保护。 |
| **多协议与订阅聚合** | 基于 Sing-box 可视化编排 17 种协议，一键导出 Clash (Mihomo)、Sing-box、Surge、V2Ray 订阅，内置机场聚合测速。 |
| **实时遥测与运维** | WebSocket 2 秒级速率与流量统计、网卡自愈、地区旗帜手动覆写、流量限额熔断、日志详情排查，以及 Cloudflare 证书 / Tunnel / 优选 IP 与 Telegram Bot 告警。 |

---

## 快速部署

官方镜像 `ghcr.io/aoomee/wirearc:latest` 支持 `linux/amd64` 与 `linux/arm64`，所有数据持久化在 `/app/data`。

### Docker Compose（通用）

适用于 **1Panel、Portainer、Dockge** 或任意 Linux 服务器，直接保存为 `compose.yaml` 后执行 `docker compose up -d`：

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

> - **端口暴露**：默认仅监听本机 `127.0.0.1:7878`，配合 HTTPS 反向代理最安全；如需公网 `IP:7878` 直连，改为 `- "7878:8080"` 并在防火墙放行。
> - **安全建议**：生产环境建议将 `WIREARC_TRUSTED_PROXIES` 收敛为实际反向代理来源 IP（详见 [反代指南](docs/reverse-proxy.md)）。

<details>
<summary>命令行一键拉取 / Docker Run</summary>

**拉取仓库标准编排**

```bash
mkdir -p /opt/wirearc && cd /opt/wirearc
curl -fsSL https://raw.githubusercontent.com/aoomee/wirearc/main/compose.yaml -o compose.yaml
docker compose up -d
```

**Docker Run**

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

| 变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `WIREARC_INITIAL_ADMIN_PASSWORD` | 留空（自动生成） | 首次初始化管理员 `admin` 的密码（12–72 字符）；已有数据库时忽略。 |
| `WIREARC_TRUSTED_PROXIES` | 留空 | 可信反向代理来源 IP / CIDR（逗号分隔），用于识别真实 IP 与开启 Secure Cookie。 |
| `TZ` | `Asia/Shanghai` | 容器时区。 |

### 首次登录

默认管理员账号为 **`admin`**。若未在环境变量中指定初始密码，首次启动会自动生成高强度随机密码并写入 `./data/initial-admin-password`（权限 `0600`，不输出到日志）：

```bash
# 在编排目录查看
cat ./data/initial-admin-password

# 或在任意位置从容器读取
docker exec $(docker ps --format '{{.Names}}' | grep -i wirearc | head -n1) cat /app/data/initial-admin-password
```

> 首次登录修改密码后，该初始密码文件会自动删除。

---

## 反向代理

推荐使用 NGINX / OpenResty（含 1Panel）或 Caddy 提供 HTTPS，反代至 `http://127.0.0.1:7878`，并开启 **WebSocket** 与 **关闭缓冲（SSE）**：

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

也可临时使用本地 SSH 转发访问：`ssh -L 7878:127.0.0.1:7878 root@<服务器IP>`。详细配置见 [NGINX HTTPS 反代指南](docs/reverse-proxy.md)。

---

## 双机专线

1. 在面板「系统设置」配置公网访问地址，通过「新增节点」复制一键命令到 VPS 完成 Agent 接入（服务名 `wirearc-agent.service`，命令入口 `wa`）。
2. 在 **落地节点 B**（分组「落地」）启用 `SS` 并推送配置。
3. 在 **入口节点 A**（分组「直连」）启用 `REALITY` 并推送配置。
4. 在入口节点 A 的 `REALITY` 卡片标题栏展开出站切换为 **经 WG → SS 出站**，选择落地节点 B 并点击 **推送配置** 即可自动完成双端建链与巡检。

---

## 运维与构建

```bash
# 更新镜像
docker compose pull && docker compose up -d

# 离线镜像导入
docker load -i wirearc-v1.0.0-linux-amd64.tar.gz
docker compose up -d

# 本地源码构建
git clone https://github.com/aoomee/wirearc.git && cd wirearc
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

---

## 文档

- [NGINX HTTPS 反向代理配置](docs/reverse-proxy.md)
- [WireGuard 双机专线架构](docs/wg-agent.md)
- [开源致谢与组件说明](docs/credits.md)
