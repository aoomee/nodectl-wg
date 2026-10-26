# 集成来源

- NodeCtl：https://github.com/hobin66/nodectl ，基线 commit `b2b2738`。
- 用户提供文件：`松茸WG-Docker离线包-私密后台版-无自签证书.zip`，镜像标签 `songrong-wg:2026.10.23-http`。
- 从镜像 `/app/engine/` 复用 `deploy.py`、`remote_worker.py`、`wg_diagnostics.py`、`vendor/wg-multi-relay.sh`，保留原始内容。WG shell SHA-256：`7616aa51a4425582f3b4650d1b085c34a0fefccbf8100306dbed8586c6cca80e`。
- 从 `/app/runner.py` 复用任务运行器；将原独立面板 owner 对应的主机指纹路径改成 NodeCtl 单管理员指纹存储。没有移植原 Flask 登录、私密后台、密码管理、证书或历史任务。
- 新增 Go 任务管理与 API、NodeCtl 界面、订阅导入、Docker 依赖、测试与部署说明。

原引擎将 Xray 固定为 v26.3.27、Realm 固定为 v2.9.6，并校验下载 SHA-256。本次没有改成未经验证的 latest 下载。

保留各项目及原文件的署名和权利。本次未替上游或用户提供文件授予新许可证，未向公共仓库发布。
