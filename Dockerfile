FROM golang:1.25.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X wirearc/internal/version.Version=local" -o /wirearc .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl unzip
WORKDIR /app
COPY --from=build /wirearc /app/wirearc
ENV TZ=Asia/Shanghai
EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["/app/wirearc"]
