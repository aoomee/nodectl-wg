# NGINX HTTPS 反代与 Agent 授权

同机部署可使用以下结构，面板不用额外申请证书：

```text
浏览器 / Agent ── HTTPS / WSS ──> NGINX ── HTTP / WS ──> 面板
```

本说明适用于包含 `NODECTL_TRUSTED_PROXIES` 支持的新版本。旧版 Agent WG 曾要求真实后端 TLS，仅添加环境变量不能修复旧程序；先升级到包含本修复的镜像或自行构建。Agent 的外部地址仍需使用有效证书的 HTTPS/WSS，不能改成 HTTP/WS 或跳过证书校验。

## 1. 配置可信代理

面板默认不信任任何反代头。`NODECTL_TRUSTED_PROXIES` 接受逗号分隔的 IP 或 CIDR，判断依据是直接连接面板的 TCP 对端，**不是访客 IP、面板域名或转发头里的地址**。

原生运行面板、同机 NGINX 连接 127.0.0.1 时，可在面板服务环境变量中配置：

```text
NODECTL_TRUSTED_PROXIES=127.0.0.1,::1
```

Docker 下，即使 NGINX 访问宿主机 `127.0.0.1:7878`，面板看到的对端通常是 Docker 网桥网关，并不是 127.0.0.1。在 Compose 项目目录查看网络：

```bash
docker inspect "$(docker compose ps -q nodectl)" --format '{{range $name, $net := .NetworkSettings.Networks}}{{printf "%s: gateway=%s\n" $name $net.Gateway}}{{end}}'
```

确认所用网络以及面板登录日志中记录的直接来源。假设实际代理来源为 `172.30.0.1`，在 Compose 的 `nodectl` 服务中填写：

```yaml
environment:
  NODECTL_TRUSTED_PROXIES: "172.30.0.1"
```

若使用仓库提供的 `compose.wg.yaml`，也可以在同目录 `.env` 填写 `NODECTL_TRUSTED_PROXIES=172.30.0.1`。网页粘贴部署的 YAML 若直接写了值，则修改该值。Docker Run 使用 `-e NODECTL_TRUSTED_PROXIES=172.30.0.1`。配置后重新创建容器或重启面板进程。

`172.30.0.1` 只是示例，不能直接套用。网桥、rootless Docker 和端口转发实现可能使实际来源不同。不要配置整个 `172.16.0.0/12` 或所有私网来省事；网络重建后代理 IP 变化需要更新配置。错误的 IP/CIDR 配置会阻止面板启动，并在日志中说明。

## 2. 同机 NGINX 配置

以下 `map` 放在 NGINX 的 `http {}` 内、`server {}` 外：

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

下面放入你已有的 HTTPS 域名 `server {}`。保留已有 `listen 443 ssl`、域名、证书路径，替换原来的面板 `location /`：

```nginx
location / {
    proxy_pass http://127.0.0.1:7878;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;

    # 单层代理覆盖客户端传入值，不能使用 $http_x_forwarded_proto。
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_read_timeout 300s;
    proxy_buffering off;
}
```

NGINX 的 HTTP 端口只重定向到 HTTPS。面板宿主机映射继续保留 `127.0.0.1:7878:8080`，不要向公网开放后端端口。面板设置中的外部访问地址填写 `https://你的面板域名`，Agent 使用同域的 `https://` 和 `wss://` 地址。需要自行填入端口时，两个地址的域名和端口须一致。

如果 NGINX 也在独立容器内，127.0.0.1 指向 NGINX 自己；改为隔离网络中的 `http://nodectl:8080`，并在面板信任 NGINX 容器的实际源 IP，使用稳定地址避免重建后失效。只让授权代理访问该后端网络。

跨公网机器回源应使用经过证书验证的 HTTPS，或者受控的加密隧道。可信代理配置只确定哪些头可信，不会给 NGINX 到后端的流量加密。前面还有 CDN/多级代理时，需要单独设置可信来源链和覆盖规则，不能照抄单层代理客户端 IP 配置。

## 3. 验证与排查

1. 检查 NGINX 配置有效后重新加载，通过 HTTPS 域名登录。
2. 浏览器中 `nodectl_token` 应包含 `Secure` 和 `HttpOnly`。
3. 点击“授权当前机器”，应生成一次性令牌。在该节点可信终端完成兑换并重启 Agent。
4. Agent 使用 WSS 连接后，完成协议部署，再选择 WG 出站并推送。

若出现 `HTTPS required`，检查运行版本、可信代理地址和 NGINX 的 `X-Forwarded-Proto $scheme`。若是来源拒绝，检查 Host 是否保留，以及是否通过同一 HTTPS 域名打开页面。若 Agent 连接失败，检查有效证书、外部 HTTPS/WSS 地址和 WebSocket Upgrade 配置。

更改配置前请安排维护时间。面板短暂重启后，已完整应用的 v2 配对会等待双端认证重连并核验，最长 30 秒；核验通过后才恢复订阅。未完成的部署、Agent 重启或租约过期、授权和配置变化、核验超时仍会触发阻断清理，不保证零中断。详见 [恢复机制](WG-AGENT-INTEGRATION.md#调度与面板重启恢复)。

本机 SSH 转发 HTTP 仍可用于页面管理，但不能替代远端 Agent 的有效 HTTPS/WSS 连接。未配置代理、代理未声明 HTTPS、含多个 scheme 的转发头，均不会被当作 HTTPS。

## 自动验证

Go 测试覆盖来源伪造、多跳 IP、IPv6、Cookie、授权接口和 WG 提交。`NODECTL_TEST_NGINX=/usr/sbin/nginx go test ./internal/service -run TestAuthenticatedAgentThroughHTTPSProxy -v` 使用真实 NGINX 进程、临时受信任证书和 HTTP 后端验证 WSS 命令往返、撤销与重连拒绝；没有该变量时只运行 Go TLS 代理变体。CI 强制运行 NGINX 变体。
