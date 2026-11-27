# WireGuard 双机专线架构

WireArc 通过双端受管 Agent 自动编排内核级 WireGuard 加密隧道，实现 `VLESS+REALITY → WireGuard → Shadowsocks` 专线转发，全程无需 SSH 密码或人工交换密钥。

## 转发拓扑

```text
客户端 ── VLESS+REALITY ──> 入口节点 A（现有 REALITY 入站）
                              └─ 仅此入站的 SS 出站 ── WG 私网 ──> 落地节点 B（SS 入站）──> 互联网
```

- REALITY 在入口节点 A 终结；落地节点 B 仅需启用 Shadowsocks，不要求配置 REALITY。
- 客户端订阅保留 A 原有的地址、端口、UUID、公钥与 SNI，不新增公网转发监听；A 的其他普通入站保持直连出站。
- 首版中转链路专注 TCP 转发，入口 REALITY 的 UDP 在中转态下会被显式拒绝。

## 操作流程

1. **准备落地节点 B**：在节点编辑弹窗将分组设为「落地」，添加并启用 `SS`，点击 **推送配置**。
2. **准备入口节点 A**：将分组设为「直连」，添加并启用 `REALITY`，点击 **推送配置**。
3. **开启双机专线**：在入口节点 A 的 `REALITY` 协议卡片标题栏点击出站状态胶囊，切换为 **经 WG → SS 出站**，选择落地节点 B 后点击 **推送配置**。
4. **安全修改与停用**：普通协议与 WG 出站修改分开提交；已配对期间如需修改普通协议，请先点击 **停用 WG** 并等待双端恢复直连。

## 安全与容错机制

- **密钥隔离**：落地节点 B 的 SS 凭据通过受管通道按需读取，不写入普通日志、SSE 流或配对表；入口节点 A 本地路由覆盖文件以 `0600` 原子写入。
- **Fail-Closed 阻断保护**：阻断守卫先于路由激活落盘。配置损坏、Agent 重启或授权丢失时不会静默回落直连，必须由管理员显式重试或停用。
- **配置预校验与租约守卫**：候选配置经 `sing-box check` 校验后才重载进程；路由租约 90 秒，失联自动进入阻断态；Linux 受管子进程绑定父进程退出信号。
- **版本与更新防护**：按配对维度校验单调递增修订号（新配对可在旧配对显式释放 `direct` 后从守卫态重建）；处于非直连 WG 配对状态的节点自动跳过后台定时静默更新，避免进程意外重启导致断流。

## 调度与重启恢复

- Agent 命令在状态锁外并发执行（上限 8 个配对，单次处理总超时 20 秒），慢节点不会阻塞其他配对的查询或停用。
- 健康配对每 10 秒巡检一次，订阅仅使用最近 30 秒内确认有效的配对状态。
- 面板重启后，已激活配对进入最长 30 秒的「恢复核验」窗口：依次校验 B 的 SS 摘要、WG 状态与公钥，以及 A 的 REALITY 摘要与运行路由，通过后无缝恢复订阅，不重放激活命令。

## 运行前提

- 双端均需 Linux（systemd / OpenRC）、root 权限、`ip` / `wg` 工具、内核 WireGuard 支持及 IPv4 互通，防火墙需放行双端 WG UDP 端口与 B 在 WG 私网上的 SS TCP 端口。
- 外网生产环境建议配合有效 HTTPS 证书的反向代理使用，配置详见 [NGINX HTTPS 反代配置](reverse-proxy.md)。

## 自动化验证

```bash
go vet ./...
go test ./...
go test -race ./internal/agent/... ./internal/service ./internal/server
WIREARC_TEST_SINGBOX=/path/to/sing-box-1.13.2 go test ./internal/agent/singbox -run TestWGConfigPinnedBinary -v
node tests/node-wg-ui.cjs
```
