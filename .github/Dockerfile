FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata curl unzip

WORKDIR /app

ARG TARGETARCH
COPY --chmod=755 ./bin/wirearc-linux-${TARGETARCH} /app/wirearc

VOLUME ["/app/data"]

ENV TZ=Asia/Shanghai
EXPOSE 8080
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/wirearc"]
