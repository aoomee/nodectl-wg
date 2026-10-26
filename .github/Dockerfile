FROM python:3.12-slim-bookworm

# 安装基础证书和时区数据
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY requirements-wg.txt /tmp/requirements-wg.txt
RUN pip install --no-cache-dir -r /tmp/requirements-wg.txt

# 设定工作目录为 /app
WORKDIR /app

# 接收 Docker Buildx 传进来的目标架构 (amd64 或 arm64)
ARG TARGETARCH

# 将对应的二进制文件拷贝到 /app 目录下并直接赋予执行权限（减少镜像层数，加速构建）
COPY --chmod=755 ./bin/nodectl-linux-${TARGETARCH} /app/nodectl

# 声明数据卷，提示用户挂载此目录
VOLUME ["/app/data"]

# 暴露 Web 端口
EXPOSE 8080

# 启动程序
ENTRYPOINT ["/app/nodectl"]