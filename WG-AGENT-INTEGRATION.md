# Agent 原生 WG 中转（功能分支，尚未生产发布）

## 已实现

在「编辑节点 → 添加协议」选择 WG 中转（REALITY/TCP），A 为直连入口、B 为已接入且配置 REALITY 的落地。底部推送按钮提交 WG 专用配置，不将 WG 当作 sing-box 入站协议，也不执行原 SSH 部署器。

新增：可信 HTTPS/WSS Agent 单次绑定、带修订号的持久化双端编排、受管内核 WG 与 Go TCP 转发、独立订阅条目、停用清理及节点配置依赖保护。WG-only 操作不重启 sing-box。面板失联或撤销凭证后，入口代理租约最多约 90 秒失效；隧道断开没有公网回退。

## 必须明确的限制

- 这还是本地功能分支，不是已上线或已发布镜像。
- 首版仅支持 Linux/systemd、root、现成的 ip/wg 工具、内核 WireGuard、IPv4、REALITY/TCP；每台机器只能参与一对。
- 不自动安装系统依赖、不修改系统防火墙。管理员需明确允许双端 WG UDP 端口及 B 隧道地址上的 REALITY TCP。生成的端口可从配对状态读取（UI 还需补充高级诊断展示）。
- 绑定和 WG 写接口要求实际后端 TLS；仅 X-Forwarded-Proto 不足够。普通 HTTP 回源的代理需改为可信 TLS 回源或使用面板自身 HTTPS。
- 已部署旧版 Agent 不能仅靠更新面板获取功能：先在可信服务器终端安装本仓库新版 Agent，再以短期令牌 enroll；不经 install_id 旧通道发放新凭证。
- v0.x fork 不保证被 upstream v1.x 自动更新策略采用，需要手动升级迁移。新稳定版流程已加入 Agent 二进制与独立 sha256 文件，尚未实际发布。
- 目前面板重启采用保守清理策略，不静默恢复启用；清理完成后需在 UI 重新启用。Agent 重启不自动重新开放公网监听。
- WG 卡片存在时底部推送仅处理 WG；普通协议须先配置并推送，修改已配对节点需先停用并等待清理。尚不是混合普通协议+WG 的原子推送。
- TCP 会话有 30 分钟上限、最多 128 并发；没有通用 UDP/HY2/QUIC，也没有新独立流量计量。

## 目前验证

- Go 全量单元测试与 vet；Agent/服务/接口 race 测试。
- Agent Linux amd64、arm64 交叉构建。
- 模拟双 Agent 编排、失败清理、修订与身份、订阅测试。
- Playwright 新 WG 卡片配对/停用/手机布局，原独立 WG 和日历回归。
- 内核接口所有权、非法参数先验证、重复请求/墓碑/旧修订和本地 TCP 半关闭/租约回归。

**未完成：真实 Linux 双机 WireGuard + REALITY 端到端验证。当前开发主机为 macOS，未发现 Docker 命令；mock 不代表内核、iptables 或系统服务实测。**

## 发布前待办

1. 在授权隔离 Linux 环境实测双端配置、UDP/防火墙、真实 REALITY 客户端、隧道丢失无公网回退、重启与解绑。
2. 进一步复核所有配置/删除/数据库切换/自动任务与节点锁的冲突边界；普通协议路径仍需完整 validate-before-stop/恢复改造，当前配对依赖使用保守拒绝。
3. 补齐原弹窗完整集成（不仅专用卡片夹具）及双端绑定/版本迁移演练，核对高级端口诊断和用户提示。
4. 发布前明确上述限制，取得允许后才推送生产 main / 触发镜像；不把本分支状态称为正式完成。

## 本地验证命令

```sh
go test ./...
go vet ./...
go test -race ./internal/agent/... ./internal/service ./internal/server
# Playwright 需安装在当前项目或临时测试目录；测试 HTTP 均为 mock。
bun tests/node-wg-ui.cjs
bun tests/wg-ui.cjs
bun tests/traffic-calendar-ui.cjs
```
