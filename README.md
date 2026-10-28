# NodeCtl WG 中转集成版

基于 [hobin66/nodectl](https://github.com/hobin66/nodectl) 增加 WireGuard 双机中转部署，保留原有节点、订阅和 Agent 管理功能。

**本项目镜像：`ghcr.io/aoomee/nodectl-wg:latest`**

[下载镜像离线包 / Linux 程序](https://github.com/aoomee/nodectl-wg/releases/latest) · [完整使用说明](WG-README.md) · [构建与验证记录](https://github.com/aoomee/nodectl-wg/actions/workflows/release-main.yml) · [集成来源](WG-SOURCES.md)

## Docker 一键启动

**如果你使用网页里的「粘贴部署内容 / Compose YAML」输入框**，请只粘贴下面的 YAML（从 `services:` 开始），不要粘贴 `mkdir`、`curl` 或 `docker compose` 命令：

```yaml
services:
  nodectl:
    image: ghcr.io/aoomee/nodectl-wg:latest
    restart: unless-stopped
    init: true
    environment:
      NODECTL_TRUSTED_PROXIES: "" # 按下方反代说明填写实际代理 IP
    ports:
      - "127.0.0.1:7878:8080"
    volumes:
      - ./data:/app/data
    stop_grace_period: 75s
```

**如果你使用服务器终端**，先安装 Docker 和 Docker Compose，然后执行：

```bash
mkdir -p /opt/nodectl-wg
cd /opt/nodectl-wg
curl -fL https://raw.githubusercontent.com/aoomee/nodectl-wg/main/compose.wg.yaml -o compose.yaml
docker compose pull
docker compose up -d
```

容器默认只绑定 **`127.0.0.1:7878`**，给同机 NGINX 的 HTTP 上游填写 `http://127.0.0.1:7878`，通过自己的 HTTPS 域名访问。配置 **`NODECTL_TRUSTED_PROXIES` 为面板实际看到的代理 IP**，并让 NGINX 覆盖转发头、保留 Host 和支持 WebSocket，机器授权与 WG 即可使用 HTTP 回源；不需要给面板生成自签证书。[完整 NGINX 配置与 Docker 代理地址说明](REVERSE-PROXY.md)。

可信代理功能需要包含该修复的新版本或自行构建；旧镜像不会因为添加环境变量就自动获得支持。默认不信任任何转发头，包括来自本机或 Docker 网关的头。

尚未配置域名时，可以在自己的电脑执行 SSH 转发，再访问 `http://127.0.0.1:7878`：

```bash
ssh -L 7878:127.0.0.1:7878 root@你的面板服务器IP
```

包含本修复的版本首次安装使用账号 **`admin`**，密码自动随机生成。服务启动成功后，在面板服务器终端领取：

```bash
docker compose exec nodectl cat /app/data/initial-admin-password
# 使用 compose.wg.yaml 时：
# docker compose -f compose.wg.yaml exec nodectl cat /app/data/initial-admin-password
```

直接运行程序时读取工作目录下的 `data/initial-admin-password`。文件权限为 0600，密码不会打印到日志；登录后修改密码会清理对应的初始密码文件。新密码至少 12 个字符，且不超过 72 字节。

已有数据卷沿用原账号密码，升级和重启不会重置；如果旧实例仍使用 `admin/admin`，请登录后修改。自动化部署可在首次启动时通过 `NODECTL_INITIAL_ADMIN_PASSWORD` 指定符合要求的密码，此时不生成密码文件；该变量对已有账号无效，不是密码重置开关。旧镜像仍按旧版行为运行。

输入 VPS 密码时请使用 HTTPS 或可信的 SSH 本地转发。

也可以直接使用 Docker Run：

```bash
docker run -d \
  --name nodectl-wg \
  --restart unless-stopped \
  --init \
  --stop-timeout 75 \
  -p 127.0.0.1:7878:8080 \
  -v /opt/nodectl-wg/data:/app/data \
  ghcr.io/aoomee/nodectl-wg:latest
```

镜像支持 **Linux amd64 / arm64 面板机**，Docker 会自动选择架构。**被部署的 A/B VPS 目前只支持 x86_64**，与面板机架构无关。

## 新增的 WG 功能

在面板首页点击 **「WG 中转」**：

| 模式 | 链路 | 客户端导入 |
| --- | --- | --- |
| Realm → VLESS（默认） | A Realm → WireGuard → B VLESS / REALITY | VLESS 链接 |
| VLESS → SS | A VLESS / REALITY → WireGuard → B Shadowsocks | VLESS 链接 |

填写两端 IP、SSH 账号密码和空闲业务端口，先检查连接，再部署。支持进度日志、任务停止、SSH 指纹记录、端口冲突检查和失败回滚。验证成功后可以一键加入 NodeCtl 的 Clash / V2Ray 订阅。

SSH 密码不写入任务文件。关闭页面后后台任务继续运行；同一面板同时执行一个部署任务。预检查通过不等于 WG 部署成功，只有最终业务验证成功才开放导入。

A/B 要求：Debian / Ubuntu、x86_64、systemd、Python 3、公网 IPv4、内核 WireGuard，以及 root 或能 sudo 的登录账号。云安全组需要放行实际使用的 SSH、业务 TCP 和 WG UDP 端口。

新版 Agent 的节点编辑页会分别显示节点条件、REALITY / SS 配置、机器授权和 Agent 连接状态；不可选的 SS 落地保留在列表中，可展开查看原因。已授权机器无需重复绑定；授权被撤销后，可明确确认“重新授权”再到服务器终端绑定。页面检查以已保存配置和当前连接为准，实际协议、服务器工具及 UDP 连通性仍需部署时核验。

## 离线加载镜像

从 [Releases](https://github.com/aoomee/nodectl-wg/releases/latest) 下载对应架构的 `.tar.gz`、`SHA256SUMS-*` 和 `compose.wg.yaml`。以 x86_64 的 `v0.1.1-wg` 为例：

```bash
# 只校验镜像包（校验文件中也列出了单独程序）
grep 'tar.gz$' SHA256SUMS-amd64 | sha256sum -c -
docker load -i nodectl-wg-v0.1.1-wg-linux-amd64.tar.gz
NODECTL_IMAGE=ghcr.io/aoomee/nodectl-wg:v0.1.1-wg \
  docker compose -f compose.wg.yaml up -d --pull never
```

这是可直接 `docker load` 的镜像包，已包含面板和 Python 部署依赖。**部署 A/B 时，远端服务器仍需联网下载 Xray、Realm 等组件。** 旧版 `v0.1.0-wg` 的 ZIP 是源码与程序整合包，不是离线镜像。

## 更新与迁移

更新前等待 WG 任务结束并备份 `data/`：

```bash
cd /opt/nodectl-wg
docker compose pull
docker compose up -d
docker compose logs --tail=80
```

从原版 NodeCtl 迁移时，停止旧容器，将原数据目录挂载到新容器的 `/app/data`，不要让新旧容器同时操作同一份数据库。外置 PostgreSQL 需要另行备份。

删除自定义节点只影响订阅，不会卸载两端 VPS 服务。部署失败或取消时也可能保留已经安装的服务，恢复方法见 [完整说明](WG-README.md)。

## 自行构建

```bash
git clone https://github.com/aoomee/nodectl-wg.git
cd nodectl-wg
docker compose -f compose.wg.yaml -f compose.build.yaml up -d --build
```

发布流程先执行 Go 和 Python 测试，再分别在 amd64 / arm64 Linux 环境构建并启动镜像；登录、WG 页面、鉴权 API 和运行依赖检查通过后推送 GHCR，并生成离线包。实际结果以 [Actions](https://github.com/aoomee/nodectl-wg/actions/workflows/release-main.yml) 和 Release 为准。

提交检查也会在原生 amd64 / arm64 Linux 上验证 Docker：按上面的 Compose 文件构建，分别测试源码构建镜像和发布用镜像结构，检查首次登录、密码修改、设置保存、容器正常停止，以及删除并重建容器后密码和设置是否保留、SQLite 数据库是否完整。测试使用临时数据目录和随机本机端口，不发布镜像。结果见 [提交检查](https://github.com/aoomee/nodectl-wg/actions/workflows/checks.yml)。

已有本地测试镜像时，可执行 `bash scripts/smoke-docker.sh 镜像名` 重复验证，需要 Docker Compose 和宿主机 Python 3。该脚本会创建并清理独立的临时 Compose 项目；验证容器重建的数据持久化，不代表已验证任意旧版本的数据库迁移。

尚未完成真实 A/B VPS 的整合版端到端验证；实际线路的 UDP 可达性、WG 握手和客户端访问仍需部署时确认。

原项目的完整功能介绍保存在 [上游说明存档](README-UPSTREAM.md)。部署本版本请使用本页的 `aoomee/nodectl-wg` 镜像。
