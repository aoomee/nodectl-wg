# NodeCtl · WG 中转集成版

基于 `hobin66/nodectl` 的 `b2b2738`（2026-07-24）修改。WG 引擎来自用户提供的「松茸WG-Docker离线包-私密后台版-无自签证书.zip」。此整合版维护于 [aoomee/nodectl-wg](https://github.com/aoomee/nodectl-wg)，与上游项目分开维护。预编译程序与整合包见 [Releases](https://github.com/aoomee/nodectl-wg/releases/latest)。

## 加入了什么

NodeCtl 首页新增「WG 中转」，复用原面板登录和自定义节点订阅。

- Realm → WireGuard → VLESS / REALITY：推荐默认模式。
- VLESS / REALITY → WireGuard → Shadowsocks：A 接收 VLESS，B 提供 SS 出口。
- SSH 连接、系统与端口检查、已有 WG 链路诊断；部署过程日志和停止任务。
- 部署后检查入口连接、真实 VLESS 请求、HTTPS、出口 IP 和下载校验。成功后可复制 VLESS 链接或加入 NodeCtl 的 Clash / V2Ray 订阅。
- 同一面板一次执行一个任务；最多保留 50 条记录。页面关闭不影响执行；进程重启会将未完成任务标为中断，不自动重跑。
- SSH 密码只经子进程标准输入传递，不放入参数、环境变量或任务文件；日志进行跨输出分段脱敏。完成任务后删除临时工作目录，保留 SSH 主机指纹。
- 保留原引擎的多实例隔离、端口冲突保护、凭据清理、校验和下载及失败回滚。不同入口端口可建立不同链路；同一入口的 SNI / MTU 不会静默覆盖。

## 建议用 Docker 部署

推荐直接使用本项目预构建镜像 `ghcr.io/aoomee/nodectl-wg:latest`，支持 amd64 / arm64 面板机：

```bash
docker compose -f compose.wg.yaml pull
docker compose -f compose.wg.yaml up -d
docker compose -f compose.wg.yaml logs --tail=80
```

Releases 中的 `.tar.gz` 为可 `docker load` 的离线镜像包；`v0.1.0-wg` 的 ZIP 仍是源码与程序包。离线加载、SSH 转发及 Docker Run 示例见 [首页](README.md)。目标 A/B 部署仍需联网下载代理组件。

从源码构建则使用：

```bash
docker compose -f compose.wg.yaml -f compose.build.yaml up -d --build
```

默认绑定 `127.0.0.1:7878`，通过自己的 HTTPS 反代或 SSH 转发访问。面板 HTTP 上游地址为 `http://127.0.0.1:7878`；反代需保留原始 Host、支持 WebSocket，并配置面板的可信代理 IP，见 [NGINX 反代说明](REVERSE-PROXY.md)。这个包不会生成自签证书。SSH 本地转发适用于页面管理和旧 SSH 部署流程；新版 Agent 授权仍要求对外 HTTPS/WSS。

首次安装沿用 NodeCtl 的 `admin / admin`，请先修改密码，再开放访问。输入 VPS 密码时使用 HTTPS 或可信的 SSH 本地转发。

已有 NodeCtl：先停止旧实例，备份整个 `data/`（外置 PostgreSQL 还需备份数据库），再将原数据目录挂载到 `/app/data`。不要让新旧实例同时操作同一份数据。挂载此目录后保留原账号、节点、订阅及 WG 任务。

维护命令：

```bash
docker compose -f compose.wg.yaml logs --tail=100
docker compose -f compose.wg.yaml down
docker compose -f compose.wg.yaml up -d
```

不要把镜像改回 `ghcr.io/hobin66/nodectl:latest`：上游镜像不含本次修改。更换版本前等任务结束，并备份数据。

## 不用 Docker

整合 ZIP 中的 `bin/nodectl-linux-amd64` 可用于 Linux x86_64 面板机，无需 Go 编译器。源码目录 `outputs/nodectl-linux-amd64` 是同一份本地构建产物。运行需要 Python 3.10+、Paramiko；可用虚拟环境隔离安装：

```bash
python3 -m venv .venv-wg
.venv-wg/bin/pip install -r requirements-wg.txt
chmod +x bin/nodectl-linux-amd64
NODECTL_WG_PYTHON="$PWD/.venv-wg/bin/python3" ./bin/nodectl-linux-amd64
```

请始终在同一个工作目录运行，数据写入该目录下的 `data/`。面板进程不需要加载本机 WireGuard 模块；隧道部署在远端 A/B。

## 使用顺序

1. 登录 NodeCtl，在首页点击「WG 中转」。
2. 选择链路模式，填写 A 中转、B 落地的公网 IPv4、SSH 端口、用户名、密码和空闲业务端口。默认 SNI 为 `addons.mozilla.org`，MTU 为 1280。
3. 点击「检查连接 / 诊断」。检查通过不等于 WG 已连通；首次 SSH 连接会记录指纹，后续变化会拒绝连接。
4. 重新输入密码，点击「部署并验证」。密码在提交成功后清空。
5. 任务显示「部署及业务验证通过」后，点击「加入 NodeCtl 订阅」。重复点击同一结果不会重复添加。
6. 在「自定义节点」管理链接和分流。默认加入可用节点组，沿用 NodeCtl 现有订阅配置；不额外加入 Agent 服务器列表，也不提供这条链路的 Agent 流量统计。

A/B 要求：Debian / Ubuntu、x86_64、systemd、Python 3、支持内核 WireGuard；root 或可使用同一登录密码 sudo 的账号。暂不支持 IPv6、ARM 落地、LXC / OpenVZ 容器、SSH 私钥登录。

云安全组需要允许：面板到两端 SSH、客户端和 B 到 A 的 TCP 业务端口、A 到 B 的业务端口与 WG UDP 端口。WG UDP 通常在 51820–51999 中选择，以任务日志及目标机实际配置为准。云厂商防火墙不会被程序自动修改；两端已有服务占用业务端口时会停止，不强行抢占。

## 失败、取消与恢复

- WG 阶段失败时，原引擎会尝试切回此前验证过的公网转发，仍将任务标为失败。失败不等于自动卸载，可能保留公网转发及已安装服务。
- 停止任务和面板正常退出会给部署进程约 45 秒处理远程停止与临时凭据清理。断电、强制终止或 SSH 中断时，远端状态仍需人工检查。
- 同样参数可重试。修改 SNI / MTU 或实例模式前检查已有实例；不要删除远端归属记录后强行覆盖。
- 删除「自定义节点」只影响订阅，不会卸载两台 VPS 上的服务。任务记录也不负责服务持续监控或自动修复。
- `data/wg-relay/jobs/*.json` 保存任务摘要、脱敏日志和成功订阅链接；`data/wg-relay/hosts/known_hosts` 保存 SSH 指纹。备份时与 NodeCtl 数据一起保存。这些结果含可用节点凭据，应只供管理员访问。
- 主机重装导致 SSH 指纹变化时，先独立确认新指纹，再在面板停止任务的情况下修正对应 known_hosts 条目；不要为绕过报错清空所有指纹。
- 若提示远端临时凭据未清理，恢复 SSH 后优先用同样参数重试。人工排查位置为 `/var/lib/songrong-wg/s<实例ID>/`（旧实例为 `/root/wg-ab-auto/`）；只处理本次实例，保留其他服务与 SSH 公钥。

## 验证范围

已做本地 Go 全量测试、Go vet、WG 模块与 HTTP 接口的 race 测试；Python 引擎测试覆盖两种模式、冲突检查、成功验收、失败回滚和脚本校验；浏览器测试覆盖模式选择、检查、部署、密码清空、结果导入及移动端布局。已构建 Linux amd64 程序。

发布工作流在原生 amd64 / arm64 GitHub Linux runner 中启动容器，检查登录、WG 页面、鉴权 API 和 Python / Paramiko；通过后发布镜像，结果见仓库 Actions。未在真实 A/B VPS 上完成本次整合版端到端部署，首次上线仍需验证 SSH、UDP/WG 握手、重启自启及实际客户端访问。

开发测试：

```bash
go test ./...
go vet ./...
go test -race ./internal/wgrelay ./internal/server
python3 -m unittest discover -s tests -v
# 安装 Playwright 并具备 Chrome 后：
node tests/wg-ui.cjs
```

来源与保留事项见 `WG-SOURCES.md`。
