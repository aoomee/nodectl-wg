# Agent WG：A REALITY → WG 内 SS → B 出口（v2 修正）

## 正确拓扑

```text
客户端 -- VLESS+REALITY --> A 的现有 REALITY 入站
                           └─ 仅此入站的 SS 出站 -- WG 私网 --> B 的 SS 入站 --> 互联网
```

REALITY 在 A 终结；B 不要求 REALITY。订阅保留 A 的原地址、端口、UUID、公钥与 SNI，不复用 B REALITY，不新增公网 TCP 转发监听。普通其他入站保持原直接出站。首版只启用此链路 TCP，REALITY 入站的 UDP 被明确拒绝。

## UI 与操作

1. B 在原节点编辑窗口选择落地角色，添加/启用 SS，并推送普通配置成功。
2. A 在原流程添加/启用 REALITY，并先推送普通配置成功。
3. A 的 **REALITY 卡片 → 出站方式 → 经 WG → B 的 SS 出站**，选择 B 后点击原推送配置按钮。
4. 两端需新版 `wg-reality-ss-v2` 能力及可信 HTTPS/WSS 安全绑定。旧 v1 Agent 仅允许旧链路清理，不接受 v2 激活。
5. 普通配置和 WG 出站的混合修改不能假装原子完成：当前 UI 明确拦截，要求先完成普通部署，再启用 WG。准备期间为明确选择的直连，不能宣称无泄漏的一键部署。
6. 已配对时修改普通协议需先停用并确认恢复直连，等待双端清理完成；自动失败只阻断，不自动恢复直连。

## 功能保护

- B SS method/password/port 从 B 本地有效协议配置经认证命令读取，密码不进入普通日志、SSE、DTO 或配对表；A 本地必要的含密码覆盖文件 0600 原子存储。
- 只有 A 的 `vless-in` 匹配到 SS outbound，目标为已验证的 B WG 私网地址并绑定 WG 接口。其他入站 final 为 direct-out。
- 阻断标记先于路由激活保存；启动、配置生成、重启均读取。配置损坏或授权丢失时不静默回落 direct。
- 候选配置经固定版本 sing-box 校验，再重启受管进程。失败保留阻断，必要时停止受管进程。A 的其他协议配置不变，但共享进程重启可能短暂中断其他连接。
- 路由租约 90 秒，失联后切换到阻断；Linux 受管子进程配置 parent-death 信号。状态检查同时检查 WG/TCP 和本进程路由授权，不以磁盘 active 字段充当真实运行证明。
- 持久化修订、双端步骤、资源所有权和 SS/REALITY 摘要检查。旧配对不重解释为新模式：先按原命令清理，用户明确重新配置后进入 v2。
- 自动失败/重启清理后保留阻断及节点保留记录；只有用户明确停用并获确认后恢复直连、释放记录。

## 部署前提与未完成边界

- Linux/systemd、root、已安装 ip/wg、内核 WG、IPv4，每台机器参与一对。不自动安装系统依赖/重写防火墙；需允许双端 WG UDP 端口和 B 隧道上的 SS TCP。
- 绑定和认证连接要求对外可信 HTTPS/WSS。支持面板原生 HTTPS，也支持显式配置可信代理后的 NGINX HTTPS → 本机 HTTP 回源，见 [反代配置](REVERSE-PROXY.md)。不信任未配置来源的 HTTPS 标记，Agent 证书验证保持开启。
- 面板/两端 Agent 都要升级；已有 upstream Agent 的版本比较不保证自动迁移至 fork。
- 运行状态 active 表示配置已应用、进程存活、WG 与目标 TCP 可达；**不等于真实 REALITY→SS 客户端认证和 B 出口已通过端到端验证**。
- 尚未在授权隔离 Linux 双机环境验证完整链路、真实出口、断 WG 无公网回退及生产更新迁移。当前开发主机 macOS，无 Docker。
- 本次修正尚未提交/推送或发布镜像。旧发布流程的成功不能证明修正版可用。

## 测试

- Go 配置测试覆盖入站定向、凭证保持、重启阻断、摘要变化、损坏文件、权限、修订和失败应用。
- 编排测试覆盖 A REALITY/B SS、旧链路清理/明确迁移、失败阻断、明确停用、SS 变化和订阅去重。
- Playwright 使用真实编辑弹窗模板，mock 后端，覆盖桌面/移动、普通命令 SSE、落地准备、保存竞争、草稿保护、迁移与绑定令牌清理。
- 实际固定版本 sing-box 1.13.2 已校验 blocked/active/direct 三种生成配置（只证明配置兼容，不是双机实测）。

```sh
go test ./...
go vet ./...
go test -race ./internal/agent/... ./internal/service ./internal/server
NODECTL_TEST_SINGBOX=/path/to/sing-box-1.13.2 go test ./internal/agent/singbox -run TestWGConfigPinnedBinary -v
bun tests/node-wg-ui.cjs
bun tests/wg-ui.cjs
bun tests/traffic-calendar-ui.cjs
```
