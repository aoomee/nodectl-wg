#!/usr/bin/env bash
set -Eeuo pipefail

# WireGuard multi-relay deployment helper for Debian/Ubuntu.
# One copy of this script is used on both the landing VPS and relay VPS.
# IPv4 only: landing VPS are expected to run with IPv6 disabled.

SCRIPT_VERSION="1.5.0"
WG_DIR="/etc/wireguard"
STATE_ROOT="/root/wg-multi-relay"
SELF_TARGET="/usr/local/sbin/wg-multi-relay"
LOCK_FILE="/run/wg-multi-relay.lock"
AUTO_MODE=0
TMP_PATHS=()
# 必须在顶层取值：经 stdin 运行时这里为空，而函数内的 BASH_SOURCE[0] 会变成 "bash"
SCRIPT_SOURCE=${BASH_SOURCE[0]:-}

log()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

cleanup_tmp() {
  if (( ${#TMP_PATHS[@]} > 0 )); then
    rm -rf -- "${TMP_PATHS[@]}" 2>/dev/null || true
  fi
}
trap cleanup_tmp EXIT

# make_tmp VAR [mktemp 参数]：创建临时文件或目录，脚本退出时自动删除。
make_tmp() {
  local __var=$1 __path
  shift
  __path=$(mktemp "$@")
  TMP_PATHS+=("$__path")
  printf -v "$__var" '%s' "$__path"
}

usage() {
  cat <<'EOF'
WireGuard 多中转自动部署脚本（仅 IPv4）

一条命令（推荐，在线路机执行）：
  sudo bash wg-multi-relay.sh deploy NAME LANDING_PUBLIC_IP [OPTIONS]
  脚本先预检 Realm 规则、算出本机已占用的隧道网段，再 SSH 到落地完成规划和激活（只输一次密码），
  然后启动本机隧道、检查、测试并切换 Realm。失败后修正问题，重新运行同一条命令即可。

deploy 选项：
  --service-port PORT        落地业务端口；默认从 Realm 指向落地的规则推断
  --landing-ssh-port PORT    落地 SSH 端口，默认 22
  --mtu MTU                  WireGuard MTU，范围 1280-1500，默认 1420
  --subnet-index N           指定 10.66.N.0/30；默认自动选两端都空闲的编号
  --relay-public-ip IP       明确指定线路机公网 IPv4（落地不再按 SSH 来源自动纠正）
  --realm-config / --realm-service / --realm-listen-port / --allow-active-restart  同 auto-relay
  --replace-relay            落地同名接口已配给另一台线路机时，确认改配给本机

删除隧道、回到公网 TCP：
  sudo wg-multi-relay remove wg-NAME [--landing-ssh-port PORT] [--keep-landing]
  在线路机运行：Realm 切回公网 → SSH 删除落地端 → 删除本机；在落地机运行：只删除落地端。

查看状态：
  sudo wg-multi-relay status wg-NAME

两步自动模式（线路机无法 SSH 到落地时改用分步手动模式）：
  sudo bash wg-multi-relay.sh auto-landing NAME [SERVICE_PORT] [LANDING_PUBLIC_IP] [OPTIONS]
  sudo bash wg-multi-relay.sh auto-relay PAIR_CODE [OPTIONS]
  1. 落地机运行 auto-landing，复制 PAIR_CODE。
  2. 中转机运行 auto-relay；脚本先预检 Realm 规则，再通过 SSH 把本脚本传到落地执行激活，
     随后自动检查、测试并切换 Realm。

auto-landing / landing-plan 选项：
  --subnet-index N          手动选择 10.66.N.0/30，N 范围 1-250
  --mtu MTU                 WireGuard MTU，范围 1280-1500，默认 1420
  规划尚未激活时，换参数重新运行会直接重新规划；已激活的需先 remove。

auto-relay 选项：
  --landing-ssh-port PORT    落地 SSH 端口，默认 22
  --relay-public-ip IP       明确指定中转公网 IPv4（落地不再按 SSH 来源自动纠正）
  --realm-config PATH        Realm 配置，默认 /root/.realm/config.toml
  --realm-service SERVICE    Realm 服务，默认 realm.service
  --realm-listen-port PORT   指定需要迁移的 Realm 入口端口；默认按 remote 自动识别
  --allow-active-restart     明确允许中断现有 Realm 连接，适合无人值守维护窗口

分步手动模式：
  sudo bash wg-multi-relay.sh landing-plan NAME [SERVICE_PORT] [LANDING_PUBLIC_IP] [OPTIONS]
  sudo bash wg-multi-relay.sh relay-install PAIR_CODE [RELAY_PUBLIC_IP]
  sudo bash wg-multi-relay.sh landing-activate PEER_CODE
  sudo bash wg-multi-relay.sh status CODE|wg-NAME
  sudo bash wg-multi-relay.sh realm-cutover PAIR_CODE [REALM_CONFIG] [REALM_SERVICE] [REALM_LISTEN_PORT]
  sudo bash wg-multi-relay.sh realm-rollback INTERFACE

手动模式顺序：
  1. 落地机运行 landing-plan，复制 PAIR_CODE。
  2. 中转机运行 relay-install，复制 PEER_CODE。
  3. 落地机运行 landing-activate。
  4. 中转机运行 status，确认隧道和业务端口正常。
  5. 中转机运行 realm-cutover；只有全部检查通过才会修改 Realm。

说明：
  - NAME 示例：dmit。脚本会创建 wg-dmit，接口名最长 15 个字符。
  - SERVICE_PORT 可省略；落地机会尝试从 xboard-node 唯一识别业务端口（仅 TCP）。
  - 公网 IP 可省略；检测到内网地址（NAT 机器）时会要求明确提供。
  - auto-relay 中，落地以 SSH 实际来源地址作为中转白名单，可自动适配 NAT 中转。
  - --subnet-index 10 会分配中转 10.66.10.1/30、落地 10.66.10.2/30。
  - 网段和 WireGuard 端口会避开已有接口，以及已规划但尚未激活的接口。
  - 落地云安全组需放行 WireGuard UDP 端口；脚本从 51820 起分配，可预先放行 51820-51999。
  - CN2 等存在 PMTU 问题的线路可在 auto-landing 时增加 --mtu 1280。
  - PAIR_CODE/PEER_CODE 只含公钥和地址规划，不含任何私钥。
  - Realm 只会修改 remote 指向本落地（公网 IP、解析到落地的域名或本脚本建立的旧隧道）的规则。
  - 切换后会验证 Realm 运行、端口监听和经入口的实际转发，失败自动恢复切换前配置。
  - realm-rollback 只改动本接口相关的规则，不影响其他落地和之后手动添加的规则。
  - 健康检查只覆盖 TCP；纯 UDP 协议（Hysteria2、TUIC 等）不适用。
EOF
}

# install_self_if_needed [optional]：optional 时无法自安装只告警（落地不再依赖已安装的脚本）
install_self_if_needed() {
  local source_file=$SCRIPT_SOURCE target_file=$SELF_TARGET optional=${1:-}
  case "$source_file" in
    /dev/fd/*|/proc/*/fd/*|'')
      if [[ $optional == optional ]]; then
        warn "当前脚本经管道运行，跳过自安装到 $target_file。"
        return 0
      fi
      die "auto-relay 需要把脚本文件传给落地，不支持 curl | bash 或 bash <(curl ...)。请先下载到普通文件，再运行该文件。"
      ;;
  esac
  if [[ ! -r $source_file ]]; then
    [[ -x $target_file ]] || die "无法读取当前脚本并且 $target_file 尚未安装；请先下载脚本文件后运行。"
    warn "无法读取当前脚本，继续使用已安装的 $target_file。"
    return 0
  fi
  local source_real target_real
  source_real=$(readlink -f -- "$source_file" 2>/dev/null || printf '%s' "$source_file")
  target_real=$(readlink -f -- "$target_file" 2>/dev/null || printf '%s' "$target_file")
  if [[ $source_real != "$target_real" ]]; then
    install -m 0700 -o root -g root "$source_file" "$target_file"
    [[ -s $target_file ]] || die "自安装后的脚本为空，已停止执行。"
    grep -Fxq "SCRIPT_VERSION=\"$SCRIPT_VERSION\"" "$target_file" || \
      die "自安装后的脚本版本校验失败，已停止执行。"
    ok "脚本已安装到 $target_file（v$SCRIPT_VERSION）。"
  fi
}

self_command() {
  if [[ -x $SELF_TARGET ]]; then
    printf '%s\n' "$SELF_TARGET"
  else
    printf 'bash %s\n' "$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")"
  fi
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "必须使用 root 或 sudo 运行。"
}

require_debian_family() {
  [[ -r /etc/os-release ]] || die "无法识别操作系统。"
  local info id id_like pretty
  # 在子 shell 中读取，避免 os-release 的 NAME/VERSION 等变量污染全局
  # shellcheck disable=SC1091
  info=$(. /etc/os-release && printf '%s|%s|%s' "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-unknown}")
  IFS='|' read -r id id_like pretty <<<"$info"
  case " $id $id_like " in
    *" debian "*|*" ubuntu "*) ;;
    *) die "当前仅支持 Debian/Ubuntu；检测到 $pretty。" ;;
  esac
}

acquire_lock() {
  command -v flock >/dev/null 2>&1 || return 0
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "另一个 wg-multi-relay 进程正在运行，请稍后重试。"
}

install_dependencies() {
  local missing=0 cmd
  for cmd in wg wg-quick ip ss iptables nc ping base64 sha256sum timeout ssh flock stat readlink; do
    command -v "$cmd" >/dev/null 2>&1 || missing=1
  done
  if (( missing )); then
    log "安装 WireGuard 和检查工具……"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y wireguard wireguard-tools iproute2 iptables netcat-openbsd iputils-ping \
      coreutils openssh-client util-linux
  else
    ok "所需软件已安装。"
  fi
}

require_wireguard_support() {
  local probe="wgmrp$$"
  modprobe wireguard 2>/dev/null || true
  ip link add dev "$probe" type wireguard 2>/dev/null || \
    die "内核不支持 WireGuard（OpenVZ/LXC 等容器虚拟化常见），请改用 KVM 机器或自行安装 wireguard-go。"
  ip link del dev "$probe" 2>/dev/null || true
}

valid_ipv4() {
  local ip=$1 octet
  local -a parts
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<<"$ip"
  for octet in "${parts[@]}"; do
    # 拒绝前导 0，避免 bash 按八进制解析
    [[ $octet =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( octet <= 255 )) || return 1
  done
}

valid_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 ))
}

valid_subnet_index() {
  [[ $1 =~ ^[1-9][0-9]*$ ]] && (( 10#$1 >= 1 && 10#$1 <= 250 ))
}

valid_mtu() {
  [[ $1 =~ ^[1-9][0-9]*$ ]] && (( 10#$1 >= 1280 && 10#$1 <= 1500 ))
}

ipv4_to_integer() {
  local ip=$1 a b c d
  valid_ipv4 "$ip" || return 1
  IFS=. read -r a b c d <<<"$ip"
  printf '%s\n' "$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))"
}

# 10/8、172.16/12、192.168/16、100.64/10（CGNAT）、127/8、169.254/16
is_private_ipv4() {
  local n
  n=$(ipv4_to_integer "$1") || return 1
  (( (n >> 24) == 10 || (n >> 24) == 127 || (n >> 20) == 0xAC1 || (n >> 16) == 0xC0A8 ||
     (n >> 22) == 0x191 || (n >> 16) == 0xA9FE ))
}

cidr_overlaps_subnet_index() {
  local cidr=$1 subnet_index=$2 ip prefix ip_value target_start mask range_start range_end target_end
  if [[ $cidr == */* ]]; then
    ip=${cidr%/*}
    prefix=${cidr#*/}
  else
    ip=$cidr
    prefix=32
  fi
  valid_ipv4 "$ip" || return 1
  [[ $prefix =~ ^[0-9]+$ ]] && (( 10#$prefix >= 0 && 10#$prefix <= 32 )) || return 1
  ip_value=$(ipv4_to_integer "$ip") || return 1
  target_start=$(( (10 << 24) | (66 << 16) | (10#$subnet_index << 8) ))
  target_end=$((target_start + 3))
  if (( 10#$prefix == 0 )); then
    mask=0
  else
    mask=$(( (0xFFFFFFFF << (32 - 10#$prefix)) & 0xFFFFFFFF ))
  fi
  range_start=$((ip_value & mask))
  range_end=$((range_start | (0xFFFFFFFF ^ mask)))
  (( range_start <= target_end && target_start <= range_end ))
}

valid_public_key() {
  [[ $1 =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

valid_interface() {
  [[ $1 =~ ^[A-Za-z0-9_=+.-]{1,15}$ ]]
}

detect_source_ipv4() {
  local target=${1:-1.1.1.1} ip
  ip=$(ip -4 route get "$target" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}') || true
  valid_ipv4 "${ip:-}" || die "无法从路由检测本机 IPv4（目标 $target），请在命令中明确提供。"
  printf '%s\n' "$ip"
}

route_via_iface() {
  local dest=$1 iface=$2 route
  route=$(ip -4 route get "$dest" 2>/dev/null) || return 1
  [[ " ${route//$'\n'/ } " == *" dev $iface "* ]]
}

# listening_on_port t|u PORT：先取完整输出再判断，避免 pipefail 下 grep -q 提前退出造成误判
listening_on_port() {
  local out
  out=$(ss -Hln"$1" "sport = :$2" 2>/dev/null) || return 1
  [[ -n $out ]]
}

detect_xboard_service_port() {
  local -a ports=()
  mapfile -t ports < <(
    ss -H -lntp 2>/dev/null |
      awk '/xboard-node/ {
        addr=$4
        sub(/^.*:/, "", addr)
        if (addr ~ /^[0-9]+$/ && addr != 65530) print addr
      }' | sort -nu
  )
  if (( ${#ports[@]} == 1 )); then
    printf '%s\n' "${ports[0]}"
  elif (( ${#ports[@]} == 0 )); then
    die "未发现 xboard-node 的 TCP 业务监听端口，请给 landing-plan 明确提供 SERVICE_PORT。"
  else
    die "发现多个可能的 Xboard 业务端口：${ports[*]}；请明确提供 SERVICE_PORT。"
  fi
}

sanitize_name() {
  local name=${1,,}
  name=${name//[^a-z0-9-]/-}
  name=${name#-}
  name=${name%-}
  [[ -n $name ]] || die "NAME 不能为空。"
  local iface="wg-$name"
  valid_interface "$iface" || die "生成的接口名 $iface 无效或超过 15 个字符，请缩短 NAME。"
  printf '%s\n' "$name"
}

# 列出本机所有可能占用 10.66.N.0/30 的来源，每行：类型<TAB>CIDR<TAB>说明
subnet_sources() {
  local ignore_iface=${1:-} line iface destination file line_no cidr

  while IFS= read -r line; do
    read -r _ iface _ destination _ <<<"$line"
    [[ -n $ignore_iface && $iface == "$ignore_iface" ]] && continue
    printf '地址\t%s\t%s\n' "$destination" "$line"
  done < <(ip -o -4 address show 2>/dev/null || true)

  while IFS= read -r line; do
    if [[ -n $ignore_iface && " $line " == *" dev $ignore_iface "* ]]; then
      continue
    fi
    read -r destination _ <<<"$line"
    case "$destination" in
      local|broadcast|unicast|throw|unreachable|prohibit|blackhole)
        read -r _ destination _ <<<"$line"
        ;;
      default) continue ;;
    esac
    printf '路由\t%s\t%s\n' "$destination" "$line"
  done < <(ip -o -4 route show table all 2>/dev/null || true)

  # -o 让同一行里的多个地址（如 AllowedIPs = a, b）逐个检查
  while IFS=: read -r file line_no cidr; do
    [[ -n $file ]] || continue
    if [[ -n $ignore_iface ]]; then
      case "$file" in
        "$WG_DIR/$ignore_iface".*) continue ;;
      esac
    fi
    printf '配置\t%s\t%s:%s: %s\n' "$cidr" "$file" "$line_no" "$cidr"
  done < <(grep -RnosE '10\.66\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?' "$WG_DIR" 2>/dev/null || true)
}

subnet_conflict_report() {
  local subnet_index=$1 ignore_iface=${2:-} kind cidr desc
  while IFS=$'\t' read -r kind cidr desc; do
    cidr_overlaps_subnet_index "$cidr" "$subnet_index" || continue
    printf '  %s：%s\n' "$kind" "$desc"
  done < <(subnet_sources "$ignore_iface")
}

# 一次扫描算出 1-250 中所有被占用的网段编号，逗号分隔输出
used_subnet_indexes() {
  local ignore_iface=${1:-} kind cidr desc ip prefix value mask start end lo hi n
  local base=$(( (10 << 24) | (66 << 16) ))
  local -A used=()
  while IFS=$'\t' read -r kind cidr desc; do
    if [[ $cidr == */* ]]; then
      ip=${cidr%/*}
      prefix=${cidr#*/}
    else
      ip=$cidr
      prefix=32
    fi
    valid_ipv4 "$ip" || continue
    [[ $prefix =~ ^[0-9]+$ ]] && (( 10#$prefix <= 32 )) || continue
    value=$(ipv4_to_integer "$ip")
    if (( 10#$prefix == 0 )); then
      mask=0
    else
      mask=$(( (0xFFFFFFFF << (32 - 10#$prefix)) & 0xFFFFFFFF ))
    fi
    start=$(( value & mask ))
    end=$(( start | (0xFFFFFFFF ^ mask) ))
    (( end >= base )) || continue
    # 10.66.N.0/30 覆盖 [base+256N, base+256N+3]，求与 [start, end] 相交的 N
    hi=$(( (end - base) / 256 ))
    if (( start - base - 3 <= 0 )); then
      lo=0
    else
      lo=$(( (start - base - 3 + 255) / 256 ))
    fi
    (( lo >= 1 )) || lo=1
    (( hi <= 250 )) || hi=250
    for (( n = lo; n <= hi; n++ )); do
      used[$n]=1
    done
  done < <(subnet_sources "$ignore_iface")
  local -a list=()
  for (( n = 1; n <= 250; n++ )); do
    if [[ -n ${used[$n]:-} ]]; then
      list+=("$n")
    fi
  done
  local IFS=,
  printf '%s\n' "${list[*]}"
}

subnet_in_list() {
  [[ ",$2," == *",$1,"* ]]
}

assert_subnet_available() {
  local subnet_index=$1 ignore_iface=${2:-} report
  valid_subnet_index "$subnet_index" || die "网段编号无效：$subnet_index（允许 1-250）。"
  report=$(subnet_conflict_report "$subnet_index" "$ignore_iface")
  if [[ -n $report ]]; then
    printf '[FAIL] 10.66.%s.0/30 与本机现有地址、路由或 WireGuard 配置冲突：\n%s\n' \
      "$subnet_index" "$report" >&2
    exit 1
  fi
}

# next_subnet_index [IGNORE_IFACE] [EXCLUDE_LIST]：EXCLUDE_LIST 是线路机已占用的编号
next_subnet_index() {
  local ignore_iface=${1:-} exclude=${2:-} used n
  used=$(used_subnet_indexes "$ignore_iface")
  for (( n = 1; n <= 250; n++ )); do
    subnet_in_list "$n" "$used" && continue
    subnet_in_list "$n" "$exclude" && continue
    printf '%s\n' "$n"
    return 0
  done
  die "10.66.1.0/30 到 10.66.250.0/30 在落地或线路机上均已占用。"
}

port_is_used() {
  local port=$1
  listening_on_port u "$port" && return 0
  grep -RqsiE "^[[:space:]]*ListenPort[[:space:]]*=[[:space:]]*${port}[[:space:]]*$" "$WG_DIR" 2>/dev/null && return 0
  # 已规划但尚未激活的接口同样占用端口
  grep -RqsFx "LISTEN_PORT=${port}" "$WG_DIR" 2>/dev/null
}

next_wireguard_port() {
  local port
  for port in $(seq 51820 51999); do
    port_is_used "$port" || { printf '%s\n' "$port"; return 0; }
  done
  die "没有找到空闲的 UDP 端口（51820-51999）。"
}

ensure_keypair() {
  local iface=$1 key_file pub_file
  key_file="$WG_DIR/${iface}.key"
  pub_file="$WG_DIR/${iface}.pub"
  install -d -m 0700 -o root -g root "$WG_DIR"
  if [[ ! -s $key_file ]]; then
    ( umask 077; wg genkey > "$key_file" )
    chmod 0600 "$key_file"
    log "已为 $iface 生成新密钥。"
  else
    ok "复用 $iface 已存在的私钥。"
  fi
  wg pubkey < "$key_file" > "$pub_file"
  chmod 0644 "$pub_file"
}

encode_file() {
  base64 -w 0 "$1"
}

decode_code() {
  local code=$1 target=$2
  [[ -n $code ]] || die "交换码为空。"
  printf '%s' "$code" | base64 -d > "$target" 2>/dev/null || die "交换码不是有效的 Base64。"
  [[ -s $target ]] || die "交换码内容为空。"
}

read_payload() {
  local file=$1 line key value
  unset PAYLOAD_TYPE PAIR_ID NAME IFACE LANDING_ENDPOINT LISTEN_PORT LANDING_ADDR LANDING_IP
  unset RELAY_ADDR RELAY_IP LANDING_PUB RELAY_PUB RELAY_PUBLIC_IP MTU SERVICE_PORT
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == *=* ]] || continue
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      PAYLOAD_TYPE|PAIR_ID|NAME|IFACE|LANDING_ENDPOINT|LISTEN_PORT|LANDING_ADDR|LANDING_IP|RELAY_ADDR|RELAY_IP|LANDING_PUB|RELAY_PUB|RELAY_PUBLIC_IP|MTU|SERVICE_PORT)
        printf -v "$key" '%s' "$value"
        ;;
    esac
  done < "$file"
}

validate_pair_payload() {
  [[ ${PAYLOAD_TYPE:-} == WG_MULTI_PAIR_V1 ]] || die "PAIR_CODE 类型不正确。"
  [[ ${PAIR_ID:-} =~ ^[a-f0-9]{16}$ ]] || die "PAIR_ID 无效。"
  valid_interface "${IFACE:-}" || die "接口名无效。"
  valid_ipv4 "${LANDING_ENDPOINT:-}" || die "落地公网 IP 无效。"
  valid_port "${LISTEN_PORT:-}" || die "WireGuard 端口无效。"
  valid_ipv4 "${LANDING_IP:-}" || die "落地隧道 IP 无效。"
  valid_ipv4 "${RELAY_IP:-}" || die "中转隧道 IP 无效。"
  valid_public_key "${LANDING_PUB:-}" || die "落地公钥无效。"
  valid_port "${SERVICE_PORT:-}" || die "业务端口无效。"
  valid_mtu "${MTU:-}" || die "MTU 无效。"
  validate_tunnel_plan
}

validate_peer_payload() {
  [[ ${PAYLOAD_TYPE:-} == WG_MULTI_PEER_V1 ]] || die "PEER_CODE 类型不正确。"
  [[ ${PAIR_ID:-} =~ ^[a-f0-9]{16}$ ]] || die "PAIR_ID 无效。"
  valid_interface "${IFACE:-}" || die "接口名无效。"
  valid_ipv4 "${LANDING_ENDPOINT:-}" || die "落地公网 IP 无效。"
  valid_port "${LISTEN_PORT:-}" || die "WireGuard 端口无效。"
  valid_ipv4 "${LANDING_IP:-}" || die "落地隧道 IP 无效。"
  valid_ipv4 "${RELAY_IP:-}" || die "中转隧道 IP 无效。"
  valid_public_key "${LANDING_PUB:-}" || die "落地公钥无效。"
  valid_public_key "${RELAY_PUB:-}" || die "中转公钥无效。"
  valid_ipv4 "${RELAY_PUBLIC_IP:-}" || die "中转公网 IP 无效。"
  valid_port "${SERVICE_PORT:-}" || die "业务端口无效。"
  valid_mtu "${MTU:-}" || die "MTU 无效。"
  validate_tunnel_plan
}

validate_tunnel_plan() {
  local relay_index landing_index
  [[ ${RELAY_IP:-} =~ ^10\.66\.([0-9]+)\.1$ ]] || die "中转隧道 IP 不符合 10.66.N.1。"
  relay_index=${BASH_REMATCH[1]}
  [[ ${LANDING_IP:-} =~ ^10\.66\.([0-9]+)\.2$ ]] || die "落地隧道 IP 不符合 10.66.N.2。"
  landing_index=${BASH_REMATCH[1]}
  valid_subnet_index "$relay_index" || die "隧道网段编号无效：$relay_index。"
  [[ $relay_index == "$landing_index" ]] || die "中转和落地隧道不在同一个 /30 网段。"
  [[ ${RELAY_ADDR:-} == "$RELAY_IP/30" ]] || die "中转隧道地址必须为 $RELAY_IP/30。"
  [[ ${LANDING_ADDR:-} == "$LANDING_IP/30" ]] || die "落地隧道地址必须为 $LANDING_IP/30。"
}

tunnel_subnet_index() {
  [[ ${RELAY_IP:-} =~ ^10\.66\.([0-9]+)\.1$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# 落地只信任本机 .pair 中的规划，PEER_CODE 里的同名字段必须与之完全一致
assert_matches_local_pair() {
  local pair_file=$1 key
  for key in PAIR_ID NAME IFACE LANDING_ENDPOINT LISTEN_PORT LANDING_ADDR LANDING_IP RELAY_ADDR RELAY_IP LANDING_PUB MTU SERVICE_PORT; do
    grep -qFx "$key=${!key}" "$pair_file" || \
      die "PEER_CODE 中的 $key=${!key} 与本机规划 $pair_file 不一致，拒绝激活。"
  done
}

# atomic_install_text TARGET MODE CONTENT：内容原样写入（不解释反斜杠），末尾补一个换行。
atomic_install_text() {
  local target=$1 mode=$2 content=$3 tmp
  make_tmp tmp "${target}.tmp.XXXXXX"
  printf '%s\n' "$content" > "$tmp"
  chmod "$mode" "$tmp"
  chown root:root "$tmp"
  mv -f "$tmp" "$target"
}

config_unchanged() {
  local file=$1 content=$2
  [[ -f $file && "$(<"$file")" == "$content" ]]
}

backup_file() {
  local file=$1 backup
  backup="$file.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a -- "$file" "$backup"
  printf '%s\n' "$backup"
}

validate_wg_config() {
  local iface=$1 content=$2 dir
  make_tmp dir -d
  ( umask 077; printf '%s\n' "$content" > "$dir/$iface.conf" )
  wg-quick strip "$dir/$iface.conf" >/dev/null
}

owner_matches() {
  local owner_file=$1 role=$2 pair_id=$3
  [[ -r $owner_file ]] || return 1
  grep -Fxq "ROLE=$role" "$owner_file" && grep -Fxq "PAIR_ID=$pair_id" "$owner_file"
}

write_owner() {
  local owner_file=$1 role=$2 pair_id=$3
  atomic_install_text "$owner_file" 0600 "$(printf '%s\n' \
    'SCRIPT=wg-multi-relay' "VERSION=$SCRIPT_VERSION" "ROLE=$role" "PAIR_ID=$pair_id")"
}

# deploy 先在线路机生成密钥、后拿到配对码，期间用“待配对”记录占住这个接口名
write_pending_owner() {
  local owner_file=$1 landing_ip=$2
  atomic_install_text "$owner_file" 0600 "$(printf '%s\n' \
    'SCRIPT=wg-multi-relay' "VERSION=$SCRIPT_VERSION" 'ROLE=relay' 'PAIR_ID=pending' "PENDING_LANDING=$landing_ip")"
}

owner_pending_for() {
  local owner_file=$1 landing_ip=$2
  [[ -r $owner_file ]] || return 1
  grep -Fxq 'ROLE=relay' "$owner_file" && grep -Fxq 'PAIR_ID=pending' "$owner_file" && \
    grep -Fxq "PENDING_LANDING=$landing_ip" "$owner_file"
}

latest_handshake() {
  local iface=$1
  { wg show "$iface" latest-handshakes 2>/dev/null || true; } | awk '$2 > max {max=$2} END {print max+0}'
}

wait_for_handshake() {
  local iface=$1 max_seconds=${2:-120} waited=0 latest now
  while (( waited <= max_seconds )); do
    latest=$(latest_handshake "$iface")
    now=$(date +%s)
    if (( latest > 0 && now - latest <= 180 )); then
      ok "$iface 已完成 WireGuard 握手。"
      return 0
    fi
    if (( waited == max_seconds )); then
      break
    fi
    printf '[WAIT] 等待 %s 握手（%ss/%ss）……\n' "$iface" "$waited" "$max_seconds"
    sleep 5
    waited=$((waited + 5))
  done
  return 1
}

run_tcp_test() {
  local ip=$1 port=$2 attempts=${3:-100} ok_count=0 fail_count=0 i start end elapsed
  for i in $(seq 1 "$attempts"); do
    start=$(date +%s%3N)
    if timeout 3 bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null; then
      ok_count=$((ok_count + 1))
    else
      fail_count=$((fail_count + 1))
    fi
    end=$(date +%s%3N)
    elapsed=$((end - start))
    if (( i % 20 == 0 || i == attempts )); then
      printf '[TEST] %s/%s success=%s failure=%s last=%sms\n' "$i" "$attempts" "$ok_count" "$fail_count" "$elapsed"
    fi
  done
  printf 'TCP_TEST_RESULT target=%s:%s attempts=%s success=%s failure=%s failure_rate=%s%%\n' \
    "$ip" "$port" "$attempts" "$ok_count" "$fail_count" "$((fail_count * 100 / attempts))"
  (( fail_count == 0 ))
}

cmd_landing_plan() {
  local raw_name=${1:-}
  [[ -n $raw_name ]] || die "请提供 NAME，例如：landing-plan dmit"
  shift || true
  local requested_port="" requested_endpoint="" requested_subnet_index="" requested_mtu="" exclude="" arg
  # 位置参数按格式识别：IPv4 视为落地公网 IP，数字视为业务端口
  while (( $# > 0 )) && [[ $1 != --* ]]; do
    arg=$1
    shift
    if valid_ipv4 "$arg"; then
      [[ -z $requested_endpoint ]] || die "重复提供落地公网 IP：$arg"
      requested_endpoint=$arg
    elif valid_port "$arg"; then
      [[ -z $requested_port ]] || die "重复提供业务端口：$arg"
      requested_port=$arg
    else
      die "无法识别的参数：$arg（应为业务端口或落地公网 IPv4）。"
    fi
  done
  while (( $# > 0 )); do
    case "$1" in
      --subnet-index)
        (( $# >= 2 )) || die "--subnet-index 缺少编号。"
        requested_subnet_index=$2
        shift 2
        ;;
      --mtu)
        (( $# >= 2 )) || die "--mtu 缺少数值。"
        requested_mtu=$2
        shift 2
        ;;
      --exclude-subnets)
        (( $# >= 2 )) || die "--exclude-subnets 缺少编号列表。"
        exclude=$2
        shift 2
        ;;
      *) die "landing-plan 未知选项：$1" ;;
    esac
  done
  [[ -z $requested_subnet_index ]] || \
    valid_subnet_index "$requested_subnet_index" || \
    die "--subnet-index 必须是 1-250。"
  [[ -z $requested_mtu ]] || valid_mtu "$requested_mtu" || \
    die "--mtu 必须是 1280-1500。"
  [[ -z $exclude || $exclude =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--exclude-subnets 的格式应为 1,2,3。"
  if [[ -n $requested_subnet_index ]] && subnet_in_list "$requested_subnet_index" "$exclude"; then
    die "网段 10.66.${requested_subnet_index}.0/30 已被线路机占用，请换一个编号。"
  fi

  local name iface pair_file owner_file key_file conf_file
  local endpoint="" service_port="" subnet_index="" mtu="" listen_port="" replan=1
  local -a changes=()
  name=$(sanitize_name "$raw_name")
  iface="wg-$name"
  pair_file="$WG_DIR/${iface}.pair"
  owner_file="$WG_DIR/${iface}.owner"
  key_file="$WG_DIR/${iface}.key"
  conf_file="$WG_DIR/${iface}.conf"

  install_dependencies
  require_wireguard_support
  install -d -m 0700 -o root -g root "$STATE_ROOT"
  if [[ -s $pair_file ]]; then
    owner_matches "$owner_file" landing "$(grep '^PAIR_ID=' "$pair_file" | cut -d= -f2-)" || \
      die "$pair_file 已存在但不是本脚本创建的落地规划，拒绝覆盖。"
    [[ -s $key_file ]] || die "$pair_file 存在，但对应私钥缺失，拒绝重新生成。"
    read_payload "$pair_file"
    validate_pair_payload
    endpoint=$LANDING_ENDPOINT
    service_port=$SERVICE_PORT
    mtu=$MTU
    listen_port=$LISTEN_PORT
    subnet_index=$(tunnel_subnet_index) || die "$pair_file 的隧道网段无效。"
    if [[ -n $requested_endpoint && $requested_endpoint != "$endpoint" ]]; then
      changes+=("落地 IP $endpoint → $requested_endpoint")
      endpoint=$requested_endpoint
    fi
    if [[ -n $requested_port && $requested_port != "$service_port" ]]; then
      changes+=("业务端口 $service_port → $requested_port")
      service_port=$requested_port
    fi
    if [[ -n $requested_mtu && $requested_mtu != "$mtu" ]]; then
      changes+=("MTU $mtu → $requested_mtu")
      mtu=$requested_mtu
    fi
    if [[ -n $requested_subnet_index && $requested_subnet_index != "$subnet_index" ]]; then
      changes+=("网段 $subnet_index → $requested_subnet_index")
      subnet_index=$requested_subnet_index
    elif [[ -z $requested_subnet_index ]] && subnet_in_list "$subnet_index" "$exclude"; then
      changes+=("网段 $subnet_index 已被线路机占用，改为自动选择")
      subnet_index=""
    fi
    if (( ${#changes[@]} == 0 )); then
      replan=0
      ensure_keypair "$iface"
      log "发现已有规划，原样输出。"
    else
      # 未激活的规划只是几份文件，可以直接改；已激活的必须先拆除，避免改坏正在用的隧道
      [[ ! -e $conf_file ]] || \
        die "$iface 已激活，不能修改规划（${changes[*]}）。如需重建，先在线路机运行 remove $iface。"
      log "$iface 的规划尚未激活，按新参数重新规划：${changes[*]}。"
    fi
  else
    if [[ -e $key_file && ! -e $owner_file ]]; then
      die "$key_file 已存在但没有本脚本的所有权记录，拒绝复用。"
    fi
    [[ ! -e $conf_file ]] || die "$conf_file 已存在，换一个 NAME，拒绝覆盖。"
    if [[ -n $requested_endpoint ]]; then
      endpoint=$requested_endpoint
      if is_private_ipv4 "$endpoint"; then
        warn "落地 IP $endpoint 是内网地址；只有中转与落地处于同一内网时才可用。"
      fi
    else
      endpoint=$(detect_source_ipv4)
      if is_private_ipv4 "$endpoint"; then
        die "检测到的本机出口地址 $endpoint 是内网地址（NAT 机器）。请在命令中明确提供落地公网 IP，并确认 WireGuard UDP 端口已做转发。"
      fi
    fi
    service_port=${requested_port:-$(detect_xboard_service_port)}
    mtu=${requested_mtu:-1420}
    subnet_index=$requested_subnet_index
  fi

  if (( replan )); then
    if [[ -n $subnet_index ]]; then
      assert_subnet_available "$subnet_index" "$iface"
      log "使用隧道网段 10.66.${subnet_index}.0/30。"
    else
      subnet_index=$(next_subnet_index "$iface" "$exclude")
      log "自动选择隧道网段 10.66.${subnet_index}.0/30。"
    fi
    [[ -n $listen_port ]] || listen_port=$(next_wireguard_port)
    local landing_addr="10.66.${subnet_index}.2/30" relay_addr="10.66.${subnet_index}.1/30"
    local landing_pub seed pair_id payload
    ensure_keypair "$iface"
    landing_pub=$(<"$WG_DIR/${iface}.pub")
    seed="$iface|$endpoint|$listen_port|$landing_addr|$relay_addr|$landing_pub|$service_port|$mtu"
    pair_id=$(printf '%s' "$seed" | sha256sum | cut -c1-16)
    payload=$(printf '%s\n' \
      'PAYLOAD_TYPE=WG_MULTI_PAIR_V1' \
      "PAIR_ID=$pair_id" \
      "NAME=$name" \
      "IFACE=$iface" \
      "LANDING_ENDPOINT=$endpoint" \
      "LISTEN_PORT=$listen_port" \
      "LANDING_ADDR=$landing_addr" \
      "LANDING_IP=${landing_addr%/*}" \
      "RELAY_ADDR=$relay_addr" \
      "RELAY_IP=${relay_addr%/*}" \
      "LANDING_PUB=$landing_pub" \
      "MTU=$mtu" \
      "SERVICE_PORT=$service_port")
    atomic_install_text "$pair_file" 0600 "$payload"
    write_owner "$owner_file" landing "$pair_id"
  fi

  local code
  code=$(encode_file "$pair_file")
  read_payload "$pair_file"
  validate_pair_payload
  if [[ ${PLAN_QUIET:-0} == 1 ]]; then
    ok "落地规划 $IFACE：UDP $LISTEN_PORT，隧道 $RELAY_IP ⇄ $LANDING_IP，业务 $LANDING_IP:$SERVICE_PORT，MTU $MTU。"
    return 0
  fi
  printf '\n=== LANDING PLAN ===\n'
  printf 'interface:       %s\n' "$IFACE"
  printf 'landing public:  %s:%s/UDP\n' "$LANDING_ENDPOINT" "$LISTEN_PORT"
  printf 'landing tunnel:  %s\n' "$LANDING_ADDR"
  printf 'relay tunnel:    %s\n' "$RELAY_ADDR"
  printf 'service target:  %s:%s\n' "$LANDING_IP" "$SERVICE_PORT"
  printf 'mtu:             %s\n' "$MTU"
  printf 'public key:      %s\n' "$LANDING_PUB"
  printf '\nPAIR_CODE=%s\n' "$code"
  printf '\n自动模式：在中转机运行 auto-relay，并把上面的 PAIR_CODE 作为参数。\n'
  printf '手动模式：在中转机运行 relay-install。\n'
}

cmd_relay_install() {
  local code=${1:-} requested_public_ip=${2:-} tmp pair_payload_raw relay_public_ip
  if [[ -n $requested_public_ip ]]; then
    valid_ipv4 "$requested_public_ip" || die "中转公网 IP 无效：$requested_public_ip"
  fi
  make_tmp tmp
  decode_code "$code" "$tmp"
  read_payload "$tmp"
  validate_pair_payload
  pair_payload_raw=$(<"$tmp")

  # 在改动本机之前确定中转公网 IP；按到落地的实际路由取源地址
  if [[ -n $requested_public_ip ]]; then
    relay_public_ip=$requested_public_ip
  else
    relay_public_ip=$(detect_source_ipv4 "$LANDING_ENDPOINT")
    if is_private_ipv4 "$relay_public_ip" && ! is_private_ipv4 "$LANDING_ENDPOINT"; then
      if (( AUTO_MODE )); then
        warn "中转出口地址 $relay_public_ip 是内网地址（NAT 机器）；落地会改用 SSH 看到的来源地址作为白名单。"
      else
        die "中转出口地址 $relay_public_ip 是内网地址（NAT 机器），请在 relay-install 末尾明确提供中转公网 IPv4。"
      fi
    fi
  fi

  install_dependencies
  require_wireguard_support
  install -d -m 0700 -o root -g root "$STATE_ROOT"
  local subnet_index pair_file="$WG_DIR/${IFACE}.pair" owner_file="$WG_DIR/${IFACE}.owner"
  local conf_file="$WG_DIR/${IFACE}.conf" service="wg-quick@${IFACE}.service" changed=0
  subnet_index=$(tunnel_subnet_index) || die "PAIR_CODE 的隧道网段无效。"
  assert_subnet_available "$subnet_index" "$IFACE"
  if [[ -e $conf_file ]] && ! owner_matches "$owner_file" relay "$PAIR_ID"; then
    die "$conf_file 已存在且不属于本次配对，拒绝覆盖。"
  fi
  if [[ -e "$WG_DIR/${IFACE}.key" ]] && ! owner_matches "$owner_file" relay "$PAIR_ID" && \
     ! owner_pending_for "$owner_file" "$LANDING_ENDPOINT"; then
    die "$WG_DIR/${IFACE}.key 已存在且不属于本次配对，拒绝复用。"
  fi
  ensure_keypair "$IFACE"
  atomic_install_text "$pair_file" 0600 "$pair_payload_raw"
  write_owner "$owner_file" relay "$PAIR_ID"

  local private_key config relay_pub peer_payload peer_file peer_code
  private_key=$(<"$WG_DIR/${IFACE}.key")
  config=$(printf '%s\n' \
    '[Interface]' \
    "Address = $RELAY_ADDR" \
    "PrivateKey = $private_key" \
    "MTU = $MTU" \
    '' \
    '[Peer]' \
    "PublicKey = $LANDING_PUB" \
    "Endpoint = $LANDING_ENDPOINT:$LISTEN_PORT" \
    "AllowedIPs = $LANDING_IP/32" \
    'PersistentKeepalive = 25')
  unset private_key
  if config_unchanged "$conf_file" "$config"; then
    ok "中转 WireGuard 配置未变化。"
  else
    validate_wg_config "$IFACE" "$config" || die "生成的中转 WireGuard 配置无效。"
    if [[ -e $conf_file ]]; then
      backup_file "$conf_file" >/dev/null
    fi
    atomic_install_text "$conf_file" 0600 "$config"
    changed=1
  fi
  systemctl enable "$service"
  if ! systemctl is-active --quiet "$service"; then
    systemctl start "$service"
  elif (( changed )); then
    systemctl restart "$service"
  fi

  relay_pub=$(<"$WG_DIR/${IFACE}.pub")
  peer_payload=$(printf '%s\n' \
    'PAYLOAD_TYPE=WG_MULTI_PEER_V1' \
    "PAIR_ID=$PAIR_ID" \
    "NAME=$NAME" \
    "IFACE=$IFACE" \
    "LANDING_ENDPOINT=$LANDING_ENDPOINT" \
    "LISTEN_PORT=$LISTEN_PORT" \
    "LANDING_ADDR=$LANDING_ADDR" \
    "LANDING_IP=$LANDING_IP" \
    "RELAY_ADDR=$RELAY_ADDR" \
    "RELAY_IP=$RELAY_IP" \
    "LANDING_PUB=$LANDING_PUB" \
    "RELAY_PUB=$relay_pub" \
    "RELAY_PUBLIC_IP=$relay_public_ip" \
    "MTU=$MTU" \
    "SERVICE_PORT=$SERVICE_PORT")
  peer_file="$WG_DIR/${IFACE}.peer"
  atomic_install_text "$peer_file" 0600 "$peer_payload"
  peer_code=$(encode_file "$peer_file")

  if (( AUTO_MODE )); then
    ok "中转端 $IFACE 已安装并启动。"
    return 0
  fi
  ok "中转端 $IFACE 已安装并启动。落地尚未激活前无握手属于正常现象。"
  printf '\nPEER_CODE=%s\n' "$peer_code"
  printf '\n手动模式下一步：回到落地机运行 landing-activate，并把上面的 PEER_CODE 作为参数。\n'
}

cmd_landing_activate() {
  local code=${1:-} auto=0 keep_relay_ip=0 no_wait=0 replace_relay=0 tmp
  shift || true
  while (( $# > 0 )); do
    case "$1" in
      --auto) auto=1 ;;
      --keep-relay-ip) keep_relay_ip=1 ;;
      --no-wait) no_wait=1 ;;
      --replace-relay) replace_relay=1 ;;
      *) die "landing-activate 未知选项：$1" ;;
    esac
    shift
  done
  make_tmp tmp
  decode_code "$code" "$tmp"
  read_payload "$tmp"
  validate_peer_payload

  local pair_file="$WG_DIR/${IFACE}.pair" owner_file="$WG_DIR/${IFACE}.owner"
  local key_file="$WG_DIR/${IFACE}.key" conf_file="$WG_DIR/${IFACE}.conf"
  local service="wg-quick@${IFACE}.service" subnet_index actual_landing_pub
  [[ -s $pair_file ]] || die "缺少 $pair_file；请先在本机运行 landing-plan $NAME。"
  owner_matches "$owner_file" landing "$PAIR_ID" || die "本机规划与 PEER_CODE 的 PAIR_ID 不匹配。"
  assert_matches_local_pair "$pair_file"
  [[ -s $key_file ]] || die "缺少落地私钥 $key_file。"

  install_dependencies
  require_wireguard_support
  actual_landing_pub=$(wg pubkey < "$key_file")
  [[ $actual_landing_pub == "$LANDING_PUB" ]] || die "本机落地公钥与 PEER_CODE 不匹配。"
  subnet_index=$(tunnel_subnet_index) || die "PEER_CODE 的隧道网段无效。"
  assert_subnet_available "$subnet_index" "$IFACE"

  # 已激活的接口换成另一台线路机的公钥，会让原线路机的隧道断掉，必须明确确认
  local current_peer=""
  if [[ -s $conf_file ]]; then
    current_peer=$(sed -n 's/^PublicKey = //p' "$conf_file" | head -n 1)
  fi
  if [[ -n $current_peer && $current_peer != "$RELAY_PUB" ]] && (( ! replace_relay )); then
    die "$IFACE 已与另一台线路机配对（公钥 ${current_peer:0:8}…）。换名称重新部署；或确认原线路机已弃用后，加 --replace-relay 重新运行。"
  fi

  # 自动模式下 SSH 由中转发起，SSH_CONNECTION 的来源就是中转到落地的实际出口地址
  local relay_ip=$RELAY_PUBLIC_IP seen_ip
  if (( auto )) && [[ -n ${SSH_CONNECTION:-} ]]; then
    seen_ip=${SSH_CONNECTION%% *}
    if valid_ipv4 "$seen_ip" && [[ $seen_ip != "$relay_ip" ]]; then
      if (( keep_relay_ip )); then
        warn "SSH 来源为 $seen_ip，与指定的中转公网 IP $relay_ip 不同；按指定值配置白名单。"
      else
        warn "中转上报 $relay_ip，但落地看到的 SSH 来源为 $seen_ip；白名单改用 $seen_ip。"
        relay_ip=$seen_ip
      fi
    fi
  fi
  if is_private_ipv4 "$relay_ip" && ! is_private_ipv4 "$LANDING_ENDPOINT"; then
    warn "白名单来源 $relay_ip 是内网地址；中转若在 NAT 后将无法握手。"
  fi

  # 独立链：先放行中转、再丢弃其他来源，在 INPUT 首位跳转，不受其他放行规则影响
  local chain="WGMR-$IFACE" private_key config
  private_key=$(<"$key_file")
  config=$(printf '%s\n' \
    '[Interface]' \
    "Address = $LANDING_ADDR" \
    "ListenPort = $LISTEN_PORT" \
    "PrivateKey = $private_key" \
    "MTU = $MTU" \
    "PostUp = iptables -N $chain 2>/dev/null || iptables -F $chain" \
    "PostUp = iptables -A $chain -s $relay_ip/32 -j ACCEPT" \
    "PostUp = iptables -A $chain -j DROP" \
    "PostUp = iptables -C INPUT -p udp --dport $LISTEN_PORT -j $chain 2>/dev/null || iptables -I INPUT 1 -p udp --dport $LISTEN_PORT -j $chain" \
    "PreDown = while iptables -D INPUT -p udp --dport $LISTEN_PORT -j $chain 2>/dev/null; do :; done" \
    "PreDown = iptables -F $chain 2>/dev/null || true" \
    "PreDown = iptables -X $chain 2>/dev/null || true" \
    '' \
    '[Peer]' \
    "PublicKey = $RELAY_PUB" \
    "AllowedIPs = $RELAY_IP/32")
  unset private_key

  local was_active=0 unchanged=0 backup=""
  if systemctl is-active --quiet "$service"; then
    was_active=1
  fi
  if config_unchanged "$conf_file" "$config"; then
    unchanged=1
  fi
  if (( was_active && unchanged )); then
    ok "落地 WireGuard 配置未变化且正在运行，跳过重启。"
  else
    validate_wg_config "$IFACE" "$config" || die "生成的落地 WireGuard 配置无效。"
    if (( was_active )); then
      # 先用旧配置停止，让旧配置自己的 PreDown 清理旧防火墙规则
      systemctl stop "$service"
    fi
    if [[ -e $conf_file ]] && (( ! unchanged )); then
      backup=$(backup_file "$conf_file")
    fi
    atomic_install_text "$conf_file" 0600 "$config"
    systemctl enable "$service"
    if ! systemctl start "$service"; then
      if [[ -n $backup ]]; then
        warn "新配置启动失败，恢复旧配置。"
        cp -a -- "$backup" "$conf_file"
        if (( was_active )); then
          systemctl start "$service" || true
        fi
      fi
      die "落地 WireGuard 启动失败，请查看 journalctl -u $service。"
    fi
  fi

  if (( no_wait )); then
    ok "落地端 $IFACE 已激活，只允许 $relay_ip 访问 $LISTEN_PORT/UDP；等待线路机建立握手。"
    return 0
  fi
  wait_for_handshake "$IFACE" 120 || \
    die "120 秒内没有 WireGuard 握手。配置已保留；请检查云防火墙是否放行 $LISTEN_PORT/UDP，以及白名单来源 $relay_ip 是否为中转的实际出口。"
  if ! ping -c 3 -W 2 "$RELAY_IP" >/dev/null 2>&1; then
    warn "已握手，但 Ping 中转隧道地址 $RELAY_IP 失败（中转可能过滤 ICMP），不影响后续 TCP 检查。"
  fi
  ok "落地端 $IFACE 已激活，且仅允许 $relay_ip 访问 $LISTEN_PORT/UDP。"
  printf '下一步：在中转机运行 status 或 realm-cutover。\n'
}

load_any_code() {
  local code=$1 tmp=$2
  decode_code "$code" "$tmp"
  read_payload "$tmp"
  case "${PAYLOAD_TYPE:-}" in
    WG_MULTI_PAIR_V1) validate_pair_payload ;;
    WG_MULTI_PEER_V1) validate_peer_payload ;;
    *) die "不支持的交换码类型。" ;;
  esac
}

cmd_status() {
  local code=${1:-} tmp latest now age
  # 既接受交换码，也接受接口名（deploy 模式下用户手里没有交换码）
  if valid_interface "$code" && [[ -s "$WG_DIR/${code}.pair" ]]; then
    read_payload "$WG_DIR/${code}.pair"
    validate_pair_payload
  else
    make_tmp tmp
    load_any_code "$code" "$tmp"
  fi
  owner_matches "$WG_DIR/${IFACE}.owner" relay "$PAIR_ID" || die "status 应在本次配对的中转机运行。"
  systemctl is-active --quiet "wg-quick@${IFACE}.service" || die "wg-quick@${IFACE} 未运行。"
  route_via_iface "$LANDING_IP" "$IFACE" || die "$LANDING_IP 没有通过 $IFACE 路由。"
  latest=$(latest_handshake "$IFACE")
  now=$(date +%s)
  (( latest > 0 )) || die "$IFACE 尚无握手。"
  age=$((now - latest))
  (( age <= 180 )) || die "$IFACE 最近握手已超过 180 秒。"
  if ! ping -c 3 -W 2 "$LANDING_IP"; then
    warn "Ping $LANDING_IP 失败（落地可能过滤 ICMP），继续检查 TCP。"
  fi
  nc -vz -w 3 "$LANDING_IP" "$SERVICE_PORT" || die "落地业务端口 $LANDING_IP:$SERVICE_PORT 不通。"
  printf '\n'
  wg show "$IFACE"
  printf '\n'
  ip -4 route show default
  ip -4 route get "$LANDING_IP"
  ok "$IFACE 状态正常，落地业务端口 $LANDING_IP:$SERVICE_PORT 可连接。"
}

# 把 Realm 配置拆成 endpoint 块，每块输出一行（制表符分隔，缺失字段为 -）：
# 块起始行 块结束行 listen行号 listen主机 listen端口 remote行号 remote主机 remote端口 标记
# 标记：lt=有 listen_transport，bind=有 through/interface（出站绑定源地址）。
# 兼容 mawk：只用 sub/match/substr，不用 gawk 扩展和正则区间。
realm_parse_endpoints() {
  awk '
    function value_of(line, key,    v) {
      v = line
      sub("^[ \t]*" key "[ \t]*=[ \t]*\"", "", v)
      sub("\"[ \t]*(#.*)?$", "", v)
      return v
    }
    function split_addr(v, which,    host, port) {
      if (index(v, ":") == 0) return 0
      port = v; sub(/^.*:/, "", port)
      host = v; sub(/:[^:]*$/, "", host)
      if (host == "" || port !~ /^[0-9]+$/) return 0
      if (which == "l") { l_host = host; l_port = port } else { r_host = host; r_port = port }
      return 1
    }
    function reset_block() {
      l_ln = "-"; l_host = "-"; l_port = "-"; l_bad = 0
      r_ln = "-"; r_host = "-"; r_port = "-"; r_bad = 0
      sub_table = 0; flags = ""
    }
    function flush(end_line) {
      if (in_ep) {
        if (l_bad) l_ln = "-"
        if (r_bad) r_ln = "-"
        printf "%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", start, end_line, l_ln, l_host, l_port, r_ln, r_host, r_port, (flags == "" ? "-" : flags)
      }
      in_ep = 0
    }
    /^[ \t]*\[/ {
      if ($0 ~ /^[ \t]*\[\[[ \t]*endpoints[ \t]*\]\][ \t]*(#.*)?$/) {
        flush(NR - 1); in_ep = 1; start = NR; reset_block(); next
      }
      if (in_ep && $0 ~ /^[ \t]*\[\[?[ \t]*endpoints\./) { sub_table = 1; next }
      flush(NR - 1); next
    }
    in_ep && !sub_table && /^[ \t]*listen[ \t]*=/ {
      if (l_ln != "-" || $0 !~ /^[ \t]*listen[ \t]*=[ \t]*"[^"]*"[ \t]*(#.*)?$/ || !split_addr(value_of($0, "listen"), "l")) l_bad = 1
      else l_ln = NR
      next
    }
    in_ep && !sub_table && /^[ \t]*remote[ \t]*=/ {
      if (r_ln != "-" || $0 !~ /^[ \t]*remote[ \t]*=[ \t]*"[^"]*"[ \t]*(#.*)?$/ || !split_addr(value_of($0, "remote"), "r")) r_bad = 1
      else r_ln = NR
      next
    }
    in_ep && !sub_table && /^[ \t]*listen_transport[ \t]*=/ { flags = flags "lt,"; next }
    in_ep && !sub_table && /^[ \t]*(through|interface)[ \t]*=/ { flags = flags "bind,"; next }
    END { flush(NR) }
  ' "$1"
}

realm_load_endpoints() {
  local config=$1 s e lln lh lp rln rh rp flags
  RE_START=() RE_END=() RE_LISTEN_LN=() RE_LISTEN_HOST=() RE_LISTEN_PORT=() RE_REMOTE_LN=() RE_REMOTE=() RE_FLAGS=()
  while IFS=$'\t' read -r s e lln lh lp rln rh rp flags; do
    [[ $lln =~ ^[0-9]+$ && $rln =~ ^[0-9]+$ ]] || continue
    RE_START+=("$s")
    RE_END+=("$e")
    RE_LISTEN_LN+=("$lln")
    RE_LISTEN_HOST+=("$lh")
    RE_LISTEN_PORT+=("$lp")
    RE_REMOTE_LN+=("$rln")
    RE_REMOTE+=("$rh:$rp")
    RE_FLAGS+=("$flags")
  done < <(realm_parse_endpoints "$config")
}

hostname_resolves_to() {
  local host=$1 ip=$2 addrs
  [[ $host =~ ^[A-Za-z0-9.-]+$ && $host =~ [A-Za-z] ]] || return 1
  addrs=$(timeout 5 getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u) || return 1
  grep -qFx "$ip" <<<"$addrs"
}

# 本脚本在本机建立的、指向同一落地的旧隧道地址
is_old_tunnel_of_landing() {
  local host=$1 pair owner
  [[ $host =~ ^10\.66\.[0-9]+\.2$ ]] || return 1
  for pair in "$WG_DIR"/*.pair; do
    [[ -f $pair ]] || continue
    owner=${pair%.pair}.owner
    grep -qFx "LANDING_IP=$host" "$pair" || continue
    grep -qFx "LANDING_ENDPOINT=$LANDING_ENDPOINT" "$pair" || continue
    grep -qFx 'ROLE=relay' "$owner" 2>/dev/null || continue
    return 0
  done
  return 1
}

# 判断 remote 与本次配对的关系：inner（已走隧道）/ public（落地公网）/ oldwg（旧隧道）/ other（其他落地）
realm_classify_remote() {
  local target=$1 host port
  host=${target%:*}
  port=${target##*:}
  if [[ $target == "$LANDING_IP:$SERVICE_PORT" ]]; then
    printf 'inner\n'
  elif [[ $port != "$SERVICE_PORT" ]]; then
    printf 'other\n'
  elif [[ $host == "$LANDING_ENDPOINT" ]]; then
    printf 'public\n'
  elif is_old_tunnel_of_landing "$host"; then
    printf 'oldwg\n'
  elif hostname_resolves_to "$host" "$LANDING_ENDPOINT"; then
    printf 'public\n'
  else
    printf 'other\n'
  fi
}

realm_pick_main_from_public() {
  local i old_fallback="" state_file="$STATE_ROOT/$IFACE/realm.state"
  local -a rest=() same_port=()
  if [[ -s $state_file ]]; then
    old_fallback=$(sed -n 's/^FALLBACK_PORT=//p' "$state_file" | head -n 1)
  fi
  for i in "$@"; do
    if [[ ${RE_LISTEN_PORT[$i]} != "$old_fallback" ]]; then
      rest+=("$i")
    fi
    if [[ ${RE_LISTEN_PORT[$i]} == "$SERVICE_PORT" ]]; then
      same_port+=("$i")
    fi
  done
  if [[ -n $old_fallback ]] && (( ${#rest[@]} == 1 )); then
    printf '%s\n' "${rest[0]}"
    return 0
  fi
  if (( ${#same_port[@]} == 1 )); then
    printf '%s\n' "${same_port[0]}"
    return 0
  fi
  return 1
}

# 定位本次配对的 Realm 主规则和已有公网回退，结果写入 RL_* 全局变量；
# 指向其他落地的规则一律拒绝修改。
realm_locate() {
  local config=$1 hint=${2:-} i cls
  local -a inner=() public=() oldwg=() hinted=() others=()
  RL_DONE=0 RL_MAIN="" RL_FALLBACK="" RL_ORIGINAL_CLASS="" RL_PUBLIC_REMOTE=""
  realm_load_endpoints "$config"
  (( ${#RE_START[@]} > 0 )) || \
    die "未能在 $config 中解析到任何 [[endpoints]]（需要 listen = \"host:port\" 与 remote = \"host:port\"）。"
  for i in "${!RE_START[@]}"; do
    cls=$(realm_classify_remote "${RE_REMOTE[$i]}")
    case $cls in
      inner) inner+=("$i") ;;
      public) public+=("$i") ;;
      oldwg) oldwg+=("$i") ;;
    esac
    if [[ -n $hint && ${RE_LISTEN_PORT[$i]} == "$hint" ]]; then
      hinted+=("$i")
    fi
  done

  if [[ -n $hint ]]; then
    (( ${#hinted[@]} == 1 )) || \
      die "需要在 $config 中恰好找到一个 Realm 入口端口 $hint，实际为 ${#hinted[@]} 个。"
    RL_MAIN=${hinted[0]}
    cls=$(realm_classify_remote "${RE_REMOTE[$RL_MAIN]}")
    case $cls in
      inner) RL_DONE=1; return 0 ;;
      public|oldwg) ;;
      *) die "Realm 入口 $hint 当前指向 ${RE_REMOTE[$RL_MAIN]}，不属于落地 $LANDING_ENDPOINT:$SERVICE_PORT，拒绝修改。" ;;
    esac
    (( ${#inner[@]} == 0 )) || \
      die "隧道目标 $LANDING_IP:$SERVICE_PORT 已被 Realm 入口 ${RE_LISTEN_PORT[${inner[0]}]} 使用，与指定入口 $hint 冲突。"
  else
    if (( ${#inner[@]} == 1 )); then
      RL_MAIN=${inner[0]}
      RL_DONE=1
      return 0
    fi
    (( ${#inner[@]} == 0 )) || die "发现 ${#inner[@]} 条 Realm 规则已指向 $LANDING_IP:$SERVICE_PORT，无法判断。"
    if (( ${#oldwg[@]} == 1 )); then
      RL_MAIN=${oldwg[0]}
    elif (( ${#oldwg[@]} > 1 )); then
      die "发现 ${#oldwg[@]} 条指向本落地旧隧道的 Realm 规则，请用 --realm-listen-port 指定入口。"
    elif (( ${#public[@]} == 1 )); then
      RL_MAIN=${public[0]}
    elif (( ${#public[@]} > 1 )); then
      RL_MAIN=$(realm_pick_main_from_public "${public[@]}") || \
        die "发现 ${#public[@]} 条指向 $LANDING_ENDPOINT:$SERVICE_PORT 的 Realm 规则，无法判断主入口，请用 --realm-listen-port 指定。"
    else
      die "未在 $config 中找到指向落地 $LANDING_ENDPOINT:$SERVICE_PORT 的 Realm 规则（remote 需为落地公网 IP、解析到落地的域名或本脚本建立的旧隧道地址）。"
    fi
  fi

  if [[ ${RE_FLAGS[$RL_MAIN]} == *bind,* ]]; then
    die "Realm 入口 ${RE_LISTEN_PORT[$RL_MAIN]} 设置了 through/interface（绑定出站源地址），走隧道后源地址与落地 AllowedIPs 不符；请先删除该字段再运行。"
  fi
  RL_ORIGINAL_CLASS=$(realm_classify_remote "${RE_REMOTE[$RL_MAIN]}")
  if [[ $RL_ORIGINAL_CLASS == public ]]; then
    RL_PUBLIC_REMOTE=${RE_REMOTE[$RL_MAIN]}
  else
    RL_PUBLIC_REMOTE="$LANDING_ENDPOINT:$SERVICE_PORT"
  fi
  for i in "${public[@]}"; do
    if [[ $i != "$RL_MAIN" ]]; then
      others+=("$i")
    fi
  done
  (( ${#others[@]} <= 1 )) || die "发现 ${#others[@]} 条旧公网回退，无法安全判断应保留哪一条。"
  if (( ${#others[@]} == 1 )); then
    RL_FALLBACK=${others[0]}
    [[ ${RE_LISTEN_PORT[$RL_FALLBACK]} != "${RE_LISTEN_PORT[$RL_MAIN]}" ]] || die "主入口与旧公网回退使用了同一端口。"
  fi
}

# 从线路机的 Realm 规则推断落地业务端口：指向这台落地的规则必须只用一个端口
realm_infer_service_port() {
  local config=$1 hint=${2:-} i host port
  local -A ports=()
  realm_load_endpoints "$config"
  for i in "${!RE_START[@]}"; do
    if [[ -n $hint && ${RE_LISTEN_PORT[$i]} != "$hint" ]]; then
      continue
    fi
    host=${RE_REMOTE[$i]%:*}
    port=${RE_REMOTE[$i]##*:}
    if [[ $host == "$LANDING_ENDPOINT" ]] || is_old_tunnel_of_landing "$host" || \
       hostname_resolves_to "$host" "$LANDING_ENDPOINT"; then
      ports[$port]=1
    fi
  done
  case ${#ports[@]} in
    1) printf '%s\n' "${!ports[@]}" ;;
    0) die "Realm 配置 $config 里没有指向落地 $LANDING_ENDPOINT 的规则，无法推断业务端口；请先在 Realm 添加公网转发规则，或用 --service-port 指定。" ;;
    *) die "Realm 里指向落地 $LANDING_ENDPOINT 的规则用了多个端口（${!ports[*]}），请用 --service-port 指定。" ;;
  esac
}

realm_check_basics() {
  local config=$1 service=$2
  [[ -s $config ]] || die "Realm 配置不存在：$config"
  [[ $service =~ ^[A-Za-z0-9@_.-]+\.service$ ]] || die "Realm 服务名无效：$service"
  systemctl cat "$service" >/dev/null 2>&1 || die "Realm 服务不存在：$service"
}

find_free_fallback_port() {
  local port=$1 p used
  (( port <= 65535 )) || port=11000
  while (( port <= 65535 )); do
    used=0
    for p in "${RE_LISTEN_PORT[@]}"; do
      if [[ $p == "$port" ]]; then
        used=1
        break
      fi
    done
    if (( ! used )) && ! listening_on_port t "$port" && ! listening_on_port u "$port"; then
      printf '%s\n' "$port"
      return 0
    fi
    port=$((port + 1))
  done
  die "没有找到空闲的 Realm 回退监听端口。"
}

# 写入 Realm 配置：跟随符号链接，保留原文件的权限和属主
realm_install_config() {
  local source=$1 target=$2 real mode owner tmp
  real=$(readlink -f -- "$target")
  mode=$(stat -c '%a' -- "$real")
  owner=$(stat -c '%u:%g' -- "$real")
  make_tmp tmp "${real}.wgmr.XXXXXX"
  cat -- "$source" > "$tmp"
  chmod "$mode" "$tmp"
  chown "$owner" "$tmp"
  mv -f -- "$tmp" "$real"
}

realm_render_cutover() {
  local source=$1 destination=$2 remote_ln=$3 inner=$4 add_fallback=$5 fallback_host=$6 fallback_port=$7 public=$8
  awk -v rl="$remote_ln" -v inner="$inner" -v add="$add_fallback" \
      -v fh="$fallback_host" -v fp="$fallback_port" -v pub="$public" '
    { lines[NR] = $0 }
    NR == rl { match($0, /^[ \t]*/); lines[NR] = substr($0, 1, RLENGTH) "remote = \"" inner "\"" }
    END {
      n = NR
      if (add == 1) while (n > 0 && lines[n] ~ /^[ \t]*$/) n--
      for (i = 1; i <= n; i++) print lines[i]
      if (add == 1) {
        print ""
        print "[[endpoints]]"
        print "listen = \"" fh ":" fp "\""
        print "remote = \"" pub "\""
      }
    }
  ' "$source" > "$destination"
}

realm_render_rollback() {
  local source=$1 destination=$2 remote_ln=$3 public=$4 delete_start=$5 delete_end=$6
  awk -v rl="$remote_ln" -v pub="$public" -v ds="$delete_start" -v de="$delete_end" '
    ds > 0 && NR >= ds && NR <= de { next }
    { line = $0 }
    NR == rl { match($0, /^[ \t]*/); line = substr($0, 1, RLENGTH) "remote = \"" pub "\"" }
    { lines[++n] = line }
    END {
      while (n > 0 && lines[n] ~ /^[ \t]*$/) n--
      for (i = 1; i <= n; i++) print lines[i]
    }
  ' "$source" > "$destination"
}

probe_host_for_listen() {
  local host=$1
  case "$host" in
    0.0.0.0|'[::]'|'::'|'') printf '127.0.0.1\n' ;;
    \[*\]) host=${host#[}; printf '%s\n' "${host%]}" ;;
    *) printf '%s\n' "$host" ;;
  esac
}

# 经 Realm 入口发起一个 TCP 连接，确认 Realm 随即向隧道目标建立了连接
realm_forward_probe() {
  local host=$1 port=$2 target=$3
  timeout 10 bash -c '
    exec 3<>"/dev/tcp/$1/$2" || exit 1
    for _ in $(seq 1 20); do
      if [[ -n $(ss -Htn state established dst "$3" 2>/dev/null) ]]; then
        exit 0
      fi
      sleep 0.3
    done
    exit 1
  ' _ "$host" "$port" "$target" 2>/dev/null
}

# realm_restart_and_verify SERVICE PROBE_HOST PROBE_PORT INNER_TARGET PORT...
# INNER_TARGET 为空时跳过转发探测。
realm_restart_and_verify() {
  local service=$1 probe_host=$2 probe_port=$3 inner=$4 port
  shift 4
  systemctl restart "$service" || { warn "Realm 重启失败。"; return 1; }
  sleep 3
  systemctl is-active --quiet "$service" || { warn "Realm 重启后没有保持运行。"; return 1; }
  for port in "$@"; do
    listening_on_port t "$port" || { warn "Realm 未监听 TCP $port。"; return 1; }
  done
  if [[ -n $inner ]]; then
    realm_forward_probe "$probe_host" "$probe_port" "$inner" || \
      { warn "经 Realm 入口 $probe_host:$probe_port 的探测连接没有转发到 $inner。"; return 1; }
  fi
  return 0
}

active_realm_connection_count() {
  ss -Htnp state established 2>/dev/null | grep -c '"realm"' || true
}

cmd_realm_cutover() {
  local code=${1:-} realm_config=${2:-/root/.realm/config.toml} realm_service=${3:-realm.service}
  local listen_hint=${4:-${REALM_LISTEN_PORT_HINT:-}} tmp
  make_tmp tmp
  load_any_code "$code" "$tmp"
  realm_check_basics "$realm_config" "$realm_service"
  [[ -z $listen_hint ]] || valid_port "$listen_hint" || die "Realm 入口端口无效：$listen_hint"
  owner_matches "$WG_DIR/${IFACE}.owner" relay "$PAIR_ID" || die "当前机器不是本次配对的中转端。"

  # 先识别规则（只读、很快），识别不了就不必跑 100 次测试
  local inner_target="$LANDING_IP:$SERVICE_PORT" main listen_host listen_port current_target probe_target
  realm_locate "$realm_config" "$listen_hint"
  main=$RL_MAIN
  listen_host=${RE_LISTEN_HOST[$main]}
  listen_port=${RE_LISTEN_PORT[$main]}
  current_target=${RE_REMOTE[$main]}
  if (( RL_DONE )); then
    ok "Realm 入口 $listen_port 已经使用 $inner_target，无需重复切换。"
    return 0
  fi
  probe_target=$inner_target
  if [[ ${RE_FLAGS[$main]} == *lt,* ]]; then
    warn "Realm 入口 $listen_port 启用了 listen_transport，切换后跳过经入口的转发探测，只检查运行和监听。"
    probe_target=""
  fi

  log "执行切换前健康门控……"
  systemctl is-active --quiet "wg-quick@${IFACE}.service" || die "wg-quick@${IFACE} 未运行。"
  route_via_iface "$LANDING_IP" "$IFACE" || die "$LANDING_IP 未通过 $IFACE 路由。"
  wait_for_handshake "$IFACE" 30 || die "WireGuard 握手不正常，Realm 保持不变。"
  if ! ping -c 3 -W 2 "$LANDING_IP" >/dev/null 2>&1; then
    warn "隧道 Ping 失败（落地可能过滤 ICMP），继续检查 TCP。"
  fi
  nc -z -w 3 "$LANDING_IP" "$SERVICE_PORT" || die "落地业务端口不通，Realm 保持不变。"
  run_tcp_test "$LANDING_IP" "$SERVICE_PORT" 100 || die "WireGuard TCP 100 次测试存在失败，Realm 保持不变。"

  local fallback_port fallback_created
  if [[ -n $RL_FALLBACK ]]; then
    fallback_port=${RE_LISTEN_PORT[$RL_FALLBACK]}
    fallback_created=0
    log "检测到已有公网回退：$fallback_port -> ${RE_REMOTE[$RL_FALLBACK]}，将直接复用。"
  else
    fallback_port=$(find_free_fallback_port "$((listen_port + 1000))")
    fallback_created=1
  fi
  if [[ $RL_ORIGINAL_CLASS == oldwg ]]; then
    log "检测到旧隧道目标：$listen_port -> $current_target，将迁移到 $inner_target。"
  fi

  local active_realm_connections
  active_realm_connections=$(active_realm_connection_count)
  if (( active_realm_connections > 0 )) && [[ ${ALLOW_ACTIVE_REALM_RESTART:-0} != 1 ]]; then
    if [[ ${PROMPT_ACTIVE_REALM_RESTART:-0} == 1 && -r /dev/tty ]]; then
      warn "Realm 当前有 $active_realm_connections 条已建立连接；重启会中断该服务下的全部现有连接。"
      printf '若明确接受短时断线，请输入大写 YES：' >/dev/tty
      local restart_answer
      IFS= read -r restart_answer </dev/tty || die "无法读取确认，Realm 保持不变。"
      [[ $restart_answer == YES ]] || die "未确认中断，Realm 保持不变。"
    else
      die "Realm 当前有 $active_realm_connections 条已建立连接。请在维护窗口重试；若明确允许中断，设置 ALLOW_ACTIVE_REALM_RESTART=1。"
    fi
  fi

  local state_dir="$STATE_ROOT/$IFACE" state_file="$STATE_ROOT/$IFACE/realm.state"
  local wireguard_file="$STATE_ROOT/$IFACE/realm-wireguard.toml" original_file
  install -d -m 0700 -o root -g root "$state_dir"
  original_file="$state_dir/realm-original.$(date -u +%Y%m%dT%H%M%SZ).toml"
  cat -- "$realm_config" > "$original_file"
  chmod 0600 "$original_file"
  realm_render_cutover "$realm_config" "$wireguard_file" "${RE_REMOTE_LN[$main]}" "$inner_target" \
    "$fallback_created" "$listen_host" "$fallback_port" "$RL_PUBLIC_REMOTE"
  chmod 0600 "$wireguard_file"

  # 生成结果自检：入口改指隧道，回退指向公网，其余规则不变
  local i check_main=0 check_fallback=0
  realm_load_endpoints "$wireguard_file"
  for i in "${!RE_START[@]}"; do
    if [[ ${RE_LISTEN_PORT[$i]} == "$listen_port" && ${RE_REMOTE[$i]} == "$inner_target" ]]; then
      check_main=$((check_main + 1))
    fi
    if [[ ${RE_LISTEN_PORT[$i]} == "$fallback_port" && ${RE_REMOTE[$i]} == "$RL_PUBLIC_REMOTE" ]]; then
      check_fallback=$((check_fallback + 1))
    fi
  done
  (( check_main == 1 && check_fallback == 1 )) || die "生成的 Realm 配置自检失败，Realm 保持不变。"

  install -d -m 0755 -o root -g root "/etc/systemd/system/${realm_service}.d"
  atomic_install_text "/etc/systemd/system/${realm_service}.d/${IFACE}.conf" 0644 "$(printf '%s\n' \
    '[Unit]' "After=wg-quick@${IFACE}.service" "Wants=wg-quick@${IFACE}.service")"
  systemctl daemon-reload

  realm_install_config "$wireguard_file" "$realm_config"
  if ! realm_restart_and_verify "$realm_service" "$(probe_host_for_listen "$listen_host")" "$listen_port" \
      "$probe_target" "$listen_port" "$fallback_port"; then
    warn "Realm 切换验证失败，恢复切换前配置。"
    realm_install_config "$original_file" "$realm_config"
    systemctl restart "$realm_service" || true
    die "Realm 切换失败，已恢复切换前配置（$original_file）。"
  fi

  atomic_install_text "$state_file" 0600 "$(printf '%s\n' \
    "REALM_CONFIG=$realm_config" \
    "REALM_SERVICE=$realm_service" \
    "LISTEN_HOST=$listen_host" \
    "LISTEN_PORT=$listen_port" \
    "FALLBACK_PORT=$fallback_port" \
    "FALLBACK_CREATED=$fallback_created" \
    "PUBLIC_TARGET=$RL_PUBLIC_REMOTE" \
    "INNER_TARGET=$inner_target" \
    "ORIGINAL_FILE=$original_file")"
  if [[ -n $probe_target ]]; then
    ok "Realm $listen_port -> $inner_target（已验证实际转发）"
  else
    ok "Realm $listen_port -> $inner_target（已验证运行和监听）"
  fi
  ok "公网 A/B 回退：$fallback_port -> $RL_PUBLIC_REMOTE"
  ok "切换前原始配置已保存：$original_file"
  printf '一键回滚：sudo %s realm-rollback %s\n' "$(self_command)" "$IFACE"
}

# 把一个参数包成 POSIX sh 单引号字符串，供远端 shell 解析
sq() {
  local s=${1//\'/\'\\\'\'}
  printf "'%s'" "$s"
}

require_self_for_landing() {
  [[ -r $SELF_TARGET ]] || die "缺少 $SELF_TARGET，无法把脚本传给落地执行。"
  grep -Fxq "SCRIPT_VERSION=\"$SCRIPT_VERSION\"" "$SELF_TARGET" || \
    die "$SELF_TARGET 与当前脚本版本 v$SCRIPT_VERSION 不一致，请用新版脚本文件重新运行。"
  command -v ssh >/dev/null 2>&1 || die "缺少 ssh 客户端。"
}

# ssh_landing_script HOST PORT LOG 命令 参数……
# 经 stdin 把本机脚本传到落地、装到同一路径再执行，保证两端版本一致（落地也就有了 wg-multi-relay 命令）。
# 落地输出照常显示并写入 LOG；以 WGMR_ 开头的机器可读行只写入 LOG。
ssh_landing_script() {
  local host=$1 port=$2 log=$3 arg remote_args="" remote_command
  shift 3
  for arg in "$@"; do
    remote_args+=" $(sq "$arg")"
  done
  remote_command="t=\$(mktemp) && cat > \"\$t\" && install -m 0700 \"\$t\" $SELF_TARGET && rm -f \"\$t\" && exec bash $SELF_TARGET$remote_args"
  printf '[INFO] 如未配置 SSH 密钥，请输入落地机 root 密码；密码不会被脚本保存。\n'
  ssh -p "$port" \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new \
    "root@$host" "$remote_command" < "$SELF_TARGET" | tee "$log" | { grep --line-buffered -v '^WGMR_' || true; }
}

cmd_auto_relay() {
  local code=${1:-}
  [[ -n $code ]] || die "请提供 auto-landing 生成的 PAIR_CODE。"
  shift || true
  install_self_if_needed
  AUTO_MODE=1

  local landing_ssh_port=22 requested_public_ip=""
  local realm_config=/root/.realm/config.toml realm_service=realm.service
  local realm_listen_port="" allow_active_restart=0
  while (( $# > 0 )); do
    case "$1" in
      --landing-ssh-port)
        (( $# >= 2 )) || die "--landing-ssh-port 缺少端口。"
        landing_ssh_port=$2
        shift 2
        ;;
      --relay-public-ip)
        (( $# >= 2 )) || die "--relay-public-ip 缺少 IPv4。"
        requested_public_ip=$2
        shift 2
        ;;
      --realm-config)
        (( $# >= 2 )) || die "--realm-config 缺少路径。"
        realm_config=$2
        shift 2
        ;;
      --realm-service)
        (( $# >= 2 )) || die "--realm-service 缺少服务名。"
        realm_service=$2
        shift 2
        ;;
      --realm-listen-port)
        (( $# >= 2 )) || die "--realm-listen-port 缺少端口。"
        realm_listen_port=$2
        shift 2
        ;;
      --allow-active-restart)
        allow_active_restart=1
        shift
        ;;
      *) die "auto-relay 未知选项：$1" ;;
    esac
  done
  valid_port "$landing_ssh_port" || die "落地 SSH 端口无效：$landing_ssh_port"
  if [[ -n $requested_public_ip ]]; then
    valid_ipv4 "$requested_public_ip" || die "中转公网 IP 无效：$requested_public_ip"
  fi
  if [[ -n $realm_listen_port ]]; then
    valid_port "$realm_listen_port" || die "Realm 入口端口无效：$realm_listen_port"
  fi

  local pair_tmp landing_endpoint pair_iface peer_code
  make_tmp pair_tmp
  decode_code "$code" "$pair_tmp"
  read_payload "$pair_tmp"
  validate_pair_payload
  landing_endpoint=$LANDING_ENDPOINT
  pair_iface=$IFACE

  # 在改动任何机器之前确认 Realm 规则可以被唯一、安全地识别
  log "预检：Realm 配置与规则识别……"
  realm_check_basics "$realm_config" "$realm_service"
  realm_locate "$realm_config" "$realm_listen_port"
  if (( RL_DONE )); then
    ok "Realm 入口 ${RE_LISTEN_PORT[$RL_MAIN]} 已指向 $LANDING_IP:$SERVICE_PORT。"
  else
    ok "将迁移 Realm 入口 ${RE_LISTEN_PORT[$RL_MAIN]}（当前 -> ${RE_REMOTE[$RL_MAIN]}）。"
  fi
  require_self_for_landing

  log "自动步骤 1/4：安装并启动中转端 $pair_iface……"
  cmd_relay_install "$code" "$requested_public_ip"
  peer_code=$(encode_file "$WG_DIR/${pair_iface}.peer")

  local -a activate_args=(landing-activate "$peer_code" --auto)
  if [[ -n $requested_public_ip ]]; then
    activate_args+=(--keep-relay-ip)
  fi
  log "自动步骤 2/4：通过 SSH 把脚本 v$SCRIPT_VERSION 传到落地 $landing_endpoint 并激活……"
  ssh_landing_script "$landing_endpoint" "$landing_ssh_port" /dev/null "${activate_args[@]}" || \
    die "落地端自动激活失败。中转配置已保留，Realm 未修改。"

  log "自动步骤 3/4：检查 WireGuard 和业务端口……"
  cmd_status "$code"

  log "自动步骤 4/4：执行 100 次测试并切换 Realm……"
  if (( allow_active_restart )); then
    ALLOW_ACTIVE_REALM_RESTART=1 \
      cmd_realm_cutover "$code" "$realm_config" "$realm_service" "$realm_listen_port"
  else
    PROMPT_ACTIVE_REALM_RESTART=1 \
      cmd_realm_cutover "$code" "$realm_config" "$realm_service" "$realm_listen_port"
  fi
  ok "自动部署完成：$pair_iface 已接管对应 Realm 落地链路。"
}

cmd_auto_landing() {
  install_self_if_needed optional
  cmd_landing_plan "$@"
}

# 落地端：由 deploy 经 SSH 调用，一次完成规划和激活，最后输出机器可读的配对码
cmd_landing_pair() {
  (( $# >= 3 )) || die "用法：landing-pair NAME LANDING_IP SERVICE_PORT --relay-pub KEY --relay-ip IP [选项]"
  local name=$1 endpoint=$2 service_port=$3
  shift 3
  local relay_pub="" relay_ip="" exclude="" subnet="" mtu="" keep_relay_ip=0 replace_relay=0
  while (( $# > 0 )); do
    case "$1" in
      --relay-pub)
        (( $# >= 2 )) || die "--relay-pub 缺少公钥。"
        relay_pub=$2
        shift 2
        ;;
      --relay-ip)
        (( $# >= 2 )) || die "--relay-ip 缺少 IPv4。"
        relay_ip=$2
        shift 2
        ;;
      --exclude-subnets)
        (( $# >= 2 )) || die "--exclude-subnets 缺少编号列表。"
        exclude=$2
        shift 2
        ;;
      --subnet-index)
        (( $# >= 2 )) || die "--subnet-index 缺少编号。"
        subnet=$2
        shift 2
        ;;
      --mtu)
        (( $# >= 2 )) || die "--mtu 缺少数值。"
        mtu=$2
        shift 2
        ;;
      --keep-relay-ip) keep_relay_ip=1; shift ;;
      --replace-relay) replace_relay=1; shift ;;
      *) die "landing-pair 未知选项：$1" ;;
    esac
  done
  valid_ipv4 "$endpoint" || die "落地公网 IP 无效：$endpoint"
  valid_port "$service_port" || die "业务端口无效：$service_port"
  valid_public_key "$relay_pub" || die "线路机公钥无效。"
  valid_ipv4 "$relay_ip" || die "线路机公网 IP 无效：$relay_ip"

  local -a plan_args=("$name" "$service_port" "$endpoint")
  if [[ -n $exclude ]]; then
    plan_args+=(--exclude-subnets "$exclude")
  fi
  if [[ -n $subnet ]]; then
    plan_args+=(--subnet-index "$subnet")
  fi
  if [[ -n $mtu ]]; then
    plan_args+=(--mtu "$mtu")
  fi
  PLAN_QUIET=1 cmd_landing_plan "${plan_args[@]}"

  local peer_tmp pair_code
  make_tmp peer_tmp
  printf '%s\n' \
    'PAYLOAD_TYPE=WG_MULTI_PEER_V1' \
    "PAIR_ID=$PAIR_ID" \
    "NAME=$NAME" \
    "IFACE=$IFACE" \
    "LANDING_ENDPOINT=$LANDING_ENDPOINT" \
    "LISTEN_PORT=$LISTEN_PORT" \
    "LANDING_ADDR=$LANDING_ADDR" \
    "LANDING_IP=$LANDING_IP" \
    "RELAY_ADDR=$RELAY_ADDR" \
    "RELAY_IP=$RELAY_IP" \
    "LANDING_PUB=$LANDING_PUB" \
    "RELAY_PUB=$relay_pub" \
    "RELAY_PUBLIC_IP=$relay_ip" \
    "MTU=$MTU" \
    "SERVICE_PORT=$SERVICE_PORT" > "$peer_tmp"
  pair_code=$(encode_file "$WG_DIR/${IFACE}.pair")
  local -a activate_args=("$(encode_file "$peer_tmp")" --auto --no-wait)
  if (( keep_relay_ip )); then
    activate_args+=(--keep-relay-ip)
  fi
  if (( replace_relay )); then
    activate_args+=(--replace-relay)
  fi
  cmd_landing_activate "${activate_args[@]}"
  printf 'WGMR_PAIR_CODE=%s\n' "$pair_code"
}

# 线路机：一条命令完成部署。先算出本机已占用的网段，再 SSH 到落地规划并激活（只输一次密码），
# 然后起本机隧道、检查、切换 Realm。重复运行同一条命令是安全的。
cmd_deploy() {
  local raw_name=${1:-} landing_ip=${2:-}
  [[ -n $raw_name && -n $landing_ip ]] || die "用法：deploy NAME LANDING_IP [选项]，例如：deploy hk 1.2.3.4"
  shift 2
  install_self_if_needed
  AUTO_MODE=1

  local service_port="" landing_ssh_port=22 mtu="" subnet="" requested_public_ip=""
  local realm_config=/root/.realm/config.toml realm_service=realm.service realm_listen_port=""
  local allow_active_restart=0 replace_relay=0
  while (( $# > 0 )); do
    case "$1" in
      --service-port)
        (( $# >= 2 )) || die "--service-port 缺少端口。"
        service_port=$2
        shift 2
        ;;
      --landing-ssh-port)
        (( $# >= 2 )) || die "--landing-ssh-port 缺少端口。"
        landing_ssh_port=$2
        shift 2
        ;;
      --mtu)
        (( $# >= 2 )) || die "--mtu 缺少数值。"
        mtu=$2
        shift 2
        ;;
      --subnet-index)
        (( $# >= 2 )) || die "--subnet-index 缺少编号。"
        subnet=$2
        shift 2
        ;;
      --relay-public-ip)
        (( $# >= 2 )) || die "--relay-public-ip 缺少 IPv4。"
        requested_public_ip=$2
        shift 2
        ;;
      --realm-config)
        (( $# >= 2 )) || die "--realm-config 缺少路径。"
        realm_config=$2
        shift 2
        ;;
      --realm-service)
        (( $# >= 2 )) || die "--realm-service 缺少服务名。"
        realm_service=$2
        shift 2
        ;;
      --realm-listen-port)
        (( $# >= 2 )) || die "--realm-listen-port 缺少端口。"
        realm_listen_port=$2
        shift 2
        ;;
      --allow-active-restart) allow_active_restart=1; shift ;;
      --replace-relay) replace_relay=1; shift ;;
      *) die "deploy 未知选项：$1" ;;
    esac
  done
  valid_ipv4 "$landing_ip" || die "落地公网 IP 无效：$landing_ip"
  [[ -z $service_port ]] || valid_port "$service_port" || die "业务端口无效：$service_port"
  valid_port "$landing_ssh_port" || die "落地 SSH 端口无效：$landing_ssh_port"
  [[ -z $mtu ]] || valid_mtu "$mtu" || die "--mtu 必须是 1280-1500。"
  [[ -z $subnet ]] || valid_subnet_index "$subnet" || die "--subnet-index 必须是 1-250。"
  [[ -z $requested_public_ip ]] || valid_ipv4 "$requested_public_ip" || die "线路机公网 IP 无效：$requested_public_ip"
  [[ -z $realm_listen_port ]] || valid_port "$realm_listen_port" || die "Realm 入口端口无效：$realm_listen_port"
  if is_private_ipv4 "$landing_ip"; then
    warn "落地 IP $landing_ip 是内网地址；只有两台机器在同一内网时才可用。"
  fi

  local name iface pair_file owner_file key_file conf_file existing_landing_ip="" existing_endpoint
  name=$(sanitize_name "$raw_name")
  iface="wg-$name"
  pair_file="$WG_DIR/${iface}.pair"
  owner_file="$WG_DIR/${iface}.owner"
  key_file="$WG_DIR/${iface}.key"
  conf_file="$WG_DIR/${iface}.conf"

  install_dependencies
  require_wireguard_support
  require_self_for_landing
  install -d -m 0700 -o root -g root "$WG_DIR" "$STATE_ROOT"

  # 同名接口只允许是本脚本为同一台落地建的，这样重复运行会原样复用
  if [[ -s $pair_file ]] && grep -Fxq 'ROLE=relay' "$owner_file" 2>/dev/null; then
    existing_endpoint=$(sed -n 's/^LANDING_ENDPOINT=//p' "$pair_file" | head -n 1)
    [[ $existing_endpoint == "$landing_ip" ]] || \
      die "本机的 $iface 已连接落地 $existing_endpoint。换一个名称，或先运行 remove $iface。"
    existing_landing_ip=$(sed -n 's/^LANDING_IP=//p' "$pair_file" | head -n 1)
  elif [[ -e $key_file || -e $conf_file ]] && ! owner_pending_for "$owner_file" "$landing_ip"; then
    die "$iface 的密钥或配置已存在，但不是本脚本为落地 $landing_ip 创建的，拒绝覆盖。请换一个名称。"
  fi

  # 在动任何机器之前确认 Realm 规则能被唯一、安全地识别
  log "预检：Realm 配置与规则识别……"
  realm_check_basics "$realm_config" "$realm_service"
  LANDING_ENDPOINT=$landing_ip
  LANDING_IP=$existing_landing_ip
  IFACE=$iface
  if [[ -z $service_port ]]; then
    service_port=$(realm_infer_service_port "$realm_config" "$realm_listen_port")
    log "从 Realm 规则推断落地业务端口：$service_port。"
  fi
  SERVICE_PORT=$service_port
  realm_locate "$realm_config" "$realm_listen_port"
  if (( RL_DONE )); then
    ok "Realm 入口 ${RE_LISTEN_PORT[$RL_MAIN]} 已指向隧道。"
  else
    ok "将迁移 Realm 入口 ${RE_LISTEN_PORT[$RL_MAIN]}（当前 -> ${RE_REMOTE[$RL_MAIN]}）。"
  fi

  local used
  used=$(used_subnet_indexes "$iface")
  if [[ -n $subnet ]]; then
    assert_subnet_available "$subnet" "$iface"
  fi
  log "本机已占用的隧道网段编号：${used:-无}；落地会避开这些编号。"

  if [[ ! -s $pair_file ]]; then
    ensure_keypair "$iface"
    write_pending_owner "$owner_file" "$landing_ip"
  fi
  local relay_pub relay_ip
  relay_pub=$(<"$WG_DIR/${iface}.pub")
  if [[ -n $requested_public_ip ]]; then
    relay_ip=$requested_public_ip
  else
    relay_ip=$(detect_source_ipv4 "$landing_ip")
  fi

  local -a pair_args=(landing-pair "$name" "$landing_ip" "$service_port" --relay-pub "$relay_pub" --relay-ip "$relay_ip")
  if [[ -n $used ]]; then
    pair_args+=(--exclude-subnets "$used")
  fi
  if [[ -n $subnet ]]; then
    pair_args+=(--subnet-index "$subnet")
  fi
  if [[ -n $mtu ]]; then
    pair_args+=(--mtu "$mtu")
  fi
  if [[ -n $requested_public_ip ]]; then
    pair_args+=(--keep-relay-ip)
  fi
  if (( replace_relay )); then
    pair_args+=(--replace-relay)
  fi
  local log_file code
  make_tmp log_file
  log "步骤 1/4：SSH 到落地 $landing_ip，规划并激活落地端……"
  ssh_landing_script "$landing_ip" "$landing_ssh_port" "$log_file" "${pair_args[@]}" || \
    die "落地端规划或激活失败，Realm 未修改。按上面的提示处理后，重新运行同一条命令即可。"
  code=$(sed -n 's/^WGMR_PAIR_CODE=//p' "$log_file" | tail -n 1 | tr -d '\r')
  [[ -n $code ]] || die "没有从落地拿到配对码，Realm 未修改。"

  log "步骤 2/4：安装并启动线路机端 $iface……"
  cmd_relay_install "$code" "$requested_public_ip"
  wait_for_handshake "$iface" 60 || \
    die "60 秒内没有 WireGuard 握手，Realm 未修改。请确认落地安全组放行 UDP $LISTEN_PORT，然后重新运行同一条命令。"

  log "步骤 3/4：检查隧道和业务端口……"
  cmd_status "$iface"

  log "步骤 4/4：执行 100 次测试并切换 Realm……"
  if (( allow_active_restart )); then
    ALLOW_ACTIVE_REALM_RESTART=1 \
      cmd_realm_cutover "$code" "$realm_config" "$realm_service" "$realm_listen_port"
  else
    PROMPT_ACTIVE_REALM_RESTART=1 \
      cmd_realm_cutover "$code" "$realm_config" "$realm_service" "$realm_listen_port"
  fi
  ok "部署完成：$iface 已接管 Realm 到落地 $landing_ip 的链路。"
  printf '查看状态：wg-multi-relay status %s\n' "$iface"
  printf '切回公网：wg-multi-relay realm-rollback %s\n' "$iface"
  printf '彻底删除：wg-multi-relay remove %s\n' "$iface"
}

# 状态字段统一加 ST_ 前缀，避免覆盖交换码里的同名变量（如 LISTEN_PORT）
read_state_file() {
  local file=$1 line key value
  unset ST_REALM_CONFIG ST_REALM_SERVICE ST_LISTEN_HOST ST_LISTEN_PORT ST_FALLBACK_PORT
  unset ST_FALLBACK_CREATED ST_PUBLIC_TARGET ST_INNER_TARGET ST_ORIGINAL_FILE
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == *=* ]] || continue
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      REALM_CONFIG|REALM_SERVICE|LISTEN_HOST|LISTEN_PORT|FALLBACK_PORT|FALLBACK_CREATED|PUBLIC_TARGET|INNER_TARGET|ORIGINAL_FILE)
        printf -v "ST_$key" '%s' "$value"
        ;;
    esac
  done < "$file"
}

# 定点回滚：只把本接口的入口改回公网，并删除本脚本创建的回退规则
cmd_realm_rollback() {
  local iface=${1:-}
  valid_interface "$iface" || die "请提供有效的 WireGuard 接口名。"
  local state_file="$STATE_ROOT/$iface/realm.state"
  [[ -s $state_file ]] || die "$iface 的 Realm 切换记录不存在。"
  read_state_file "$state_file"
  [[ -n ${ST_REALM_CONFIG:-} && -n ${ST_REALM_SERVICE:-} && -n ${ST_INNER_TARGET:-} && -n ${ST_PUBLIC_TARGET:-} ]] || \
    die "Realm 回滚状态损坏。"
  [[ -s $ST_REALM_CONFIG ]] || die "Realm 配置不存在：$ST_REALM_CONFIG"
  # v1.3.1 的切换每次都会重新追加回退规则，缺少该字段时按“由脚本创建”处理
  local fallback_created=${ST_FALLBACK_CREATED:-1}

  local i main="" fallback="" inner_count=0 fallback_count=0
  realm_load_endpoints "$ST_REALM_CONFIG"
  for i in "${!RE_START[@]}"; do
    if [[ ${RE_REMOTE[$i]} == "$ST_INNER_TARGET" ]]; then
      main=$i
      inner_count=$((inner_count + 1))
    fi
    if [[ $fallback_created == 1 && ${RE_LISTEN_PORT[$i]} == "${ST_FALLBACK_PORT:-}" && ${RE_REMOTE[$i]} == "$ST_PUBLIC_TARGET" ]]; then
      fallback=$i
      fallback_count=$((fallback_count + 1))
    fi
  done
  (( inner_count <= 1 )) || die "发现 $inner_count 条规则指向 $ST_INNER_TARGET，无法安全回滚。"
  (( fallback_count <= 1 )) || die "发现 $fallback_count 条回退规则使用端口 ${ST_FALLBACK_PORT:-}，无法安全回滚。"
  if [[ -z $main && -z $fallback ]]; then
    ok "Realm 中已没有 $ST_INNER_TARGET 和本脚本创建的回退，无需回滚。"
    return 0
  fi

  local remote_ln=0 delete_start=0 delete_end=0 rollback_file current_copy
  local -a ports=()
  if [[ -n $main ]]; then
    remote_ln=${RE_REMOTE_LN[$main]}
    ports+=("${RE_LISTEN_PORT[$main]}")
    if [[ ${RE_LISTEN_PORT[$main]} != "${ST_LISTEN_PORT:-}" ]]; then
      warn "指向 $ST_INNER_TARGET 的入口端口为 ${RE_LISTEN_PORT[$main]}，与切换记录 ${ST_LISTEN_PORT:-} 不同，仍按当前配置回滚。"
    fi
  else
    warn "未找到指向 $ST_INNER_TARGET 的规则，只移除公网回退。"
  fi
  if [[ -n $fallback ]]; then
    delete_start=${RE_START[$fallback]}
    delete_end=${RE_END[$fallback]}
  fi
  make_tmp rollback_file
  make_tmp current_copy
  cat -- "$ST_REALM_CONFIG" > "$current_copy"
  realm_render_rollback "$ST_REALM_CONFIG" "$rollback_file" "$remote_ln" "$ST_PUBLIC_TARGET" "$delete_start" "$delete_end"
  realm_install_config "$rollback_file" "$ST_REALM_CONFIG"
  if ! realm_restart_and_verify "$ST_REALM_SERVICE" "" "" "" "${ports[@]}"; then
    warn "回滚后 Realm 验证失败，恢复回滚前配置。"
    realm_install_config "$current_copy" "$ST_REALM_CONFIG"
    systemctl restart "$ST_REALM_SERVICE" || true
    die "Realm 回滚失败，已恢复回滚前配置。"
  fi
  ok "Realm 已恢复公网目标 $ST_PUBLIC_TARGET；WireGuard 保持运行。"
}

# 停用 wg-quick 服务，并清掉可能残留的网卡
wg_teardown() {
  local iface=$1
  systemctl disable --now "wg-quick@${iface}.service" >/dev/null 2>&1 || true
  if ip link show dev "$iface" >/dev/null 2>&1; then
    wg-quick down "$iface" >/dev/null 2>&1 || ip link del dev "$iface" 2>/dev/null || true
  fi
}

remove_wg_files() {
  local iface=$1
  rm -f -- "$WG_DIR/$iface".{conf,key,pub,pair,peer,owner} "$WG_DIR/$iface".conf.backup.*
}

remove_landing_side() {
  local iface=$1 expect_pub=${2:-} conf="$WG_DIR/$iface.conf" pair="$WG_DIR/$iface.pair"
  local current_peer="" listen_port="" chain="WGMR-$iface"
  # 由线路机发起时核对公钥，避免误删已改配给另一台线路机的同名接口
  if [[ -n $expect_pub && -s $conf ]]; then
    current_peer=$(sed -n 's/^PublicKey = //p' "$conf" | head -n 1)
    if [[ -n $current_peer && $current_peer != "$expect_pub" ]]; then
      die "落地的 $iface 已与另一台线路机配对（公钥 ${current_peer:0:8}…），不是发起删除的线路机，未做改动。"
    fi
  fi
  if [[ -s $pair ]]; then
    listen_port=$(sed -n 's/^LISTEN_PORT=//p' "$pair" | head -n 1)
  fi
  wg_teardown "$iface"
  # 服务没在运行时 PreDown 不会执行，这里兜底清理本脚本的防火墙链
  if [[ -n $listen_port ]] && command -v iptables >/dev/null 2>&1; then
    while iptables -D INPUT -p udp --dport "$listen_port" -j "$chain" 2>/dev/null; do :; done
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
  fi
  remove_wg_files "$iface"
  ok "已删除落地端 $iface。${listen_port:+云安全组里的 UDP $listen_port 可以关闭。}"
}

remove_relay_side() {
  local iface=$1 ssh_port=$2 keep_landing=$3
  local pair="$WG_DIR/$iface.pair" state_file="$STATE_ROOT/$iface/realm.state"
  local landing_ip="" inner="" relay_pub="" realm_config=/root/.realm/config.toml i
  if [[ -s $pair ]]; then
    read_payload "$pair"
    landing_ip=${LANDING_ENDPOINT:-}
    inner="${LANDING_IP:-}:${SERVICE_PORT:-}"
  else
    # deploy 中途失败时只有“待配对”记录
    landing_ip=$(sed -n 's/^PENDING_LANDING=//p' "$WG_DIR/$iface.owner" 2>/dev/null | head -n 1)
  fi
  if [[ -s "$WG_DIR/$iface.pub" ]]; then
    relay_pub=$(<"$WG_DIR/$iface.pub")
  fi

  log "步骤 1/3：Realm 切回公网……"
  if [[ -s $state_file ]]; then
    read_state_file "$state_file"
    realm_config=${ST_REALM_CONFIG:-$realm_config}
    cmd_realm_rollback "$iface"
  else
    ok "$iface 没有 Realm 切换记录，跳过。"
  fi
  # 回滚后如果仍有入口指向隧道，拆隧道会直接断流，先停下
  if [[ -n $inner && $inner != ":" && -s $realm_config ]]; then
    realm_load_endpoints "$realm_config"
    for i in "${!RE_START[@]}"; do
      if [[ ${RE_REMOTE[$i]} == "$inner" ]]; then
        die "Realm 入口 ${RE_LISTEN_PORT[$i]} 仍指向隧道 $inner，先改回公网再删除；WireGuard 未做改动。"
      fi
    done
  fi

  if (( keep_landing )); then
    warn "按 --keep-landing 保留落地端。之后可在落地机运行：wg-multi-relay remove $iface"
  elif [[ -z $landing_ip ]]; then
    warn "缺少落地信息，无法自动删除落地端。之后可在落地机运行：wg-multi-relay remove $iface"
  else
    log "步骤 2/3：SSH 到落地 $landing_ip 删除落地端……"
    require_self_for_landing
    local -a remote_args=(remove "$iface")
    if [[ -n $relay_pub ]]; then
      remote_args+=(--expect-relay-pub "$relay_pub")
    fi
    if ! ssh_landing_script "$landing_ip" "$ssh_port" /dev/null "${remote_args[@]}"; then
      warn "落地端没有删除成功，线路机这端照常删除。之后请在落地机运行：wg-multi-relay remove $iface"
    fi
  fi

  log "步骤 3/3：删除线路机端 $iface……"
  local dropin reload=0
  for dropin in /etc/systemd/system/*.service.d/"$iface".conf; do
    [[ -f $dropin ]] || continue
    grep -Fq "wg-quick@${iface}.service" "$dropin" || continue
    rm -f -- "$dropin"
    reload=1
  done
  if (( reload )); then
    systemctl daemon-reload
  fi
  wg_teardown "$iface"
  remove_wg_files "$iface"
  if [[ -d $STATE_ROOT/$iface ]]; then
    mv -- "$STATE_ROOT/$iface" "$STATE_ROOT/.removed-$iface-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  ok "已删除线路机端 $iface，Realm 已走公网直连。"
}

# remove 接口名：在线路机运行会先回滚 Realm、再经 SSH 删落地端、最后删本机；在落地机运行只删落地端
cmd_remove() {
  local iface=${1:-}
  shift || true
  valid_interface "$iface" || die "请提供接口名，例如：remove wg-hk"
  local ssh_port=22 keep_landing=0 expect_pub="" role=""
  while (( $# > 0 )); do
    case "$1" in
      --landing-ssh-port)
        (( $# >= 2 )) || die "--landing-ssh-port 缺少端口。"
        ssh_port=$2
        shift 2
        ;;
      --keep-landing) keep_landing=1; shift ;;
      --expect-relay-pub)
        (( $# >= 2 )) || die "--expect-relay-pub 缺少公钥。"
        expect_pub=$2
        shift 2
        ;;
      *) die "remove 未知选项：$1" ;;
    esac
  done
  valid_port "$ssh_port" || die "落地 SSH 端口无效：$ssh_port"
  if [[ -r "$WG_DIR/$iface.owner" ]]; then
    role=$(sed -n 's/^ROLE=//p' "$WG_DIR/$iface.owner" | head -n 1)
  fi
  case "$role" in
    landing)
      remove_landing_side "$iface" "$expect_pub"
      ;;
    relay)
      if (( ! keep_landing )); then
        install_self_if_needed
      fi
      remove_relay_side "$iface" "$ssh_port" "$keep_landing"
      ;;
    '')
      [[ ! -e "$WG_DIR/$iface.conf" ]] || die "$iface 不是本脚本创建的接口，拒绝删除。"
      ok "本机没有 $iface，无需删除。"
      ;;
    *) die "$iface 的所有权记录无法识别（ROLE=$role）。" ;;
  esac
}

main() {
  local command=${1:-help}
  shift || true
  case "$command" in
    help|-h|--help) usage; return 0 ;;
    version|-V|--version) printf '%s\n' "$SCRIPT_VERSION"; return 0 ;;
  esac
  require_root
  require_debian_family
  acquire_lock
  case "$command" in
    deploy)           cmd_deploy "$@" ;;
    remove)           cmd_remove "$@" ;;
    landing-pair)     cmd_landing_pair "$@" ;;
    auto-landing)     cmd_auto_landing "$@" ;;
    auto-relay)       cmd_auto_relay "$@" ;;
    landing-plan)     cmd_landing_plan "$@" ;;
    relay-install)    cmd_relay_install "$@" ;;
    landing-activate) cmd_landing_activate "$@" ;;
    status)           cmd_status "$@" ;;
    realm-cutover)    cmd_realm_cutover "$@" ;;
    realm-rollback)   cmd_realm_rollback "$@" ;;
    *) usage; die "未知命令：$command" ;;
  esac
}

# 经 stdin 执行（curl | bash、bash -s）时 BASH_SOURCE 为空，同样运行 main
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then
  main "$@"
fi
