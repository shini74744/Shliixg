#!/usr/bin/env bash
# nezhajc.sh
# 母机 + Incus/LXC 小鸡感染痕迹检测脚本
# 只读检测：不删除、不杀进程、不修改配置
#
# 重点：
#   1. 重点检查安装/运行哪吒监控的小鸡
#   2. 小鸡公网远端 IP 数或公网连接数 >= 1000 时标记为疑似感染
#   3. 小鸡内部只要发现乱码进程，例如 ???、????、??????，直接标记为疑似感染
#   4. 母机不会因为 UID 1000000 这类容器映射用户出现可疑进程就直接判感染
#
# 用法：
#   bash nezhajc.sh
#   bash nezhajc.sh --host-only
#   bash nezhajc.sh --nezha-only
#   bash nezhajc.sh --no-color
#
# 环境变量：
#   CONN_THRESHOLD=1000 bash nezhajc.sh
#
# 退出码：
#   0 = 未发现明显感染痕迹
#   1 = 存在可疑项，需要人工确认
#   2 = 存在高危/疑似感染项

set +e
export LC_ALL=C

SCAN_CONTAINER=1
NEZHA_ONLY=0
USE_COLOR=1
CONN_THRESHOLD="${CONN_THRESHOLD:-1000}"

for arg in "$@"; do
  case "$arg" in
    --host-only|--no-container)
      SCAN_CONTAINER=0
      ;;
    --nezha-only)
      NEZHA_ONLY=1
      ;;
    --no-color)
      USE_COLOR=0
      ;;
    -h|--help)
      cat <<HELP
用法：
  bash nezhajc.sh
  bash nezhajc.sh --host-only
  bash nezhajc.sh --nezha-only
  bash nezhajc.sh --no-color

环境变量：
  CONN_THRESHOLD=1000 bash nezhajc.sh

退出码：
  0 = 未发现明显感染痕迹
  1 = 存在可疑项，需要人工确认
  2 = 存在高危/疑似感染项
HELP
      exit 0
      ;;
  esac
done

HOST="$(hostname 2>/dev/null || echo unknown)"
TIME="$(date +%F-%H%M%S)"
REPORT="/root/nezhajc_${HOST}_${TIME}.log"

exec > >(tee -a "$REPORT") 2>&1

if [ "$USE_COLOR" -eq 1 ]; then
  RED="\033[31m"
  YELLOW="\033[33m"
  GREEN="\033[32m"
  BLUE="\033[36m"
  NC="\033[0m"
else
  RED=""
  YELLOW=""
  GREEN=""
  BLUE=""
  NC=""
fi

HOST_HIGH=0
HOST_WARN=0
ESCAPE_RISK=0

CONTAINER_INFECTED_COUNT=0
CONTAINER_WARN_COUNT=0
CONTAINER_SKIPPED_COUNT=0
CONTAINER_NEZHA_COUNT=0
CONTAINER_NEZHA_INFECTED_COUNT=0

INFECTED_LIST=""
WARN_LIST=""
SKIPPED_LIST=""
NEZHA_LIST=""
NEZHA_INFECTED_LIST=""

STRONG_RE='xmrig|kinsing|kdevtmpfsi|SystemLog|/tmp/SystemLog|/tmp/b([[:space:]]|$)|/tmp/download\.sh|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|stratum|masscan|zmap|pnscan|libusranalyse|usranalyse|ld\.so\.preload|recvp\.php|mkdir -p /root/\.ssh|chmod 700 /root/\.ssh'

SUSP_RE='xmrig|miner|kinsing|kdevtmpfsi|SystemLog|/tmp/SystemLog|/tmp/b([[:space:]]|$)|/tmp/download\.sh|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|stratum|masscan|zmap|pnscan|/dev/shm|/var/tmp|ld\.so\.preload|usranalyse|libusranalyse|recvp\.php|base64 -d|curl .*sh|wget .*sh|curl.*\|.*sh|wget.*\|.*sh|chmod \+x|chattr|mkdir -p /root/\.ssh|^[[:space:]]*[0-9]+[[:space:]]+.*\{\}'

URL_EXEC_RE='http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|curl -fsSL|curl -sL|curl -s |wget -O-|wget -qO-|wget .* -O /tmp|curl .* -o /tmp'

section() {
  echo
  echo -e "${BLUE}================ $* ================${NC}"
}

ok() {
  echo -e "${GREEN}[OK] $*${NC}"
}

warn() {
  echo -e "${YELLOW}[WARN] $*${NC}"
}

high() {
  echo -e "${RED}[HIGH] $*${NC}"
}

host_high() {
  HOST_HIGH=1
  high "$*"
}

host_warn() {
  HOST_WARN=1
  warn "$*"
}

host_ok() {
  ok "$*"
}

escape_risk() {
  ESCAPE_RISK=1
  high "$*"
}

container_infected() {
  local name="$1"
  local reason="$2"
  local nezha_flag="$3"

  CONTAINER_INFECTED_COUNT=$((CONTAINER_INFECTED_COUNT + 1))
  INFECTED_LIST="${INFECTED_LIST}
[疑似感染] ${name} | 哪吒:${nezha_flag} | 原因:${reason}"

  if [ "$nezha_flag" = "是" ]; then
    CONTAINER_NEZHA_INFECTED_COUNT=$((CONTAINER_NEZHA_INFECTED_COUNT + 1))
    NEZHA_INFECTED_LIST="${NEZHA_INFECTED_LIST}
[哪吒小鸡疑似感染] ${name} | 原因:${reason}"
  fi

  high "小鸡疑似感染：${name} | 哪吒:${nezha_flag} | 原因:${reason}"
}

container_warn() {
  local name="$1"
  local reason="$2"
  local nezha_flag="$3"

  CONTAINER_WARN_COUNT=$((CONTAINER_WARN_COUNT + 1))
  WARN_LIST="${WARN_LIST}
[可疑] ${name} | 哪吒:${nezha_flag} | 原因:${reason}"

  warn "小鸡存在可疑项：${name} | 哪吒:${nezha_flag} | 原因:${reason}"
}

container_skipped() {
  local name="$1"
  local status="$2"
  local reason="$3"

  CONTAINER_SKIPPED_COUNT=$((CONTAINER_SKIPPED_COUNT + 1))
  SKIPPED_LIST="${SKIPPED_LIST}
[未扫描] ${name} | 状态:${status} | 原因:${reason}"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_in_container() {
  local cname="$1"
  local cmd="$2"

  if has_cmd timeout; then
    timeout 35 incus exec "$cname" -- sh -c "$cmd" 2>/dev/null
  else
    incus exec "$cname" -- sh -c "$cmd" 2>/dev/null
  fi
}

section "0. 基础信息"
echo "报告文件：$REPORT"
echo "主机名：$HOST"
echo "时间：$(date)"
echo "内核：$(uname -a)"
echo "当前用户：$(id)"
echo "公网连接阈值：${CONN_THRESHOLD}"
echo "是否只扫描哪吒小鸡：${NEZHA_ONLY}"
echo

echo "虚拟化环境："
systemd-detect-virt 2>/dev/null || true
echo

echo "系统负载："
uptime 2>/dev/null || true
echo

if [ "$(id -u)" != "0" ]; then
  host_warn "当前不是 root，检测结果可能不完整"
else
  host_ok "当前是 root，权限完整"
fi

section "1. 母机 CPU / 内存最高进程"
echo "----- CPU TOP 30 -----"
ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --sort=-pcpu | head -30

echo
echo "----- 内存 TOP 30 -----"
ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --sort=-pmem | head -30

section "2. 母机感染特征扫描"

HOST_PROC_STRONG="$(ps auxww | awk '$1=="root"{print}' | grep -Eia "$STRONG_RE|$URL_EXEC_RE" | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_PROC_STRONG" ]; then
  echo "----- 母机 root 强特征可疑进程 -----"
  echo "$HOST_PROC_STRONG"
  host_high "母机 root 进程中发现强感染特征"
else
  host_ok "母机 root 进程未发现强感染特征"
fi

HOST_PROC_MAPPED="$(ps auxww | awk '$1!="root"{print}' | grep -Eia "$STRONG_RE|$URL_EXEC_RE" | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_PROC_MAPPED" ]; then
  echo
  echo "----- 非 root / 容器映射用户可疑进程，仅提示，不判定母机感染 -----"
  echo "$HOST_PROC_MAPPED"
  host_warn "母机进程表中发现容器映射侧可疑进程，需要结合小鸡扫描结果判断"
else
  host_ok "母机进程表未发现容器映射侧强特征可疑进程"
fi

section "3. 母机哪吒相关进程与服务，仅提示"
HOST_NEZHA="$(ps auxww | grep -Eia 'nezha-agent|/opt/nezha|/etc/nezha|nezha' | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_NEZHA" ]; then
  echo "----- 母机哪吒相关进程 -----"
  echo "$HOST_NEZHA"
  warn "母机存在哪吒相关进程，仅提示，不直接判定感染"
else
  ok "母机未发现哪吒相关进程"
fi

echo
echo "----- 母机哪吒相关服务/文件 -----"
HOST_NEZHA_FILES="$(find /etc/systemd/system /lib/systemd/system /opt /etc -maxdepth 4 \( -iname '*nezha*' -o -iname 'config*.yml' \) -ls 2>/dev/null | head -200 || true)"
if [ -n "$HOST_NEZHA_FILES" ]; then
  echo "$HOST_NEZHA_FILES"
else
  ok "母机未发现明显哪吒相关文件"
fi

section "4. 母机 /etc/ld.so.preload 检查"
if [ -e /etc/ld.so.preload ]; then
  PRELOAD_CONTENT="$(cat /etc/ld.so.preload 2>/dev/null || true)"
  ls -lah /etc/ld.so.preload 2>/dev/null
  lsattr /etc/ld.so.preload 2>/dev/null || true
  echo "----- 内容 -----"
  echo "$PRELOAD_CONTENT"

  echo "$PRELOAD_CONTENT" | grep -Eia 'usranalyse|libusranalyse|xmrig|miner|SystemLog|/tmp|/dev/shm|/var/tmp' >/dev/null
  if [ $? -eq 0 ]; then
    while read -r sofile; do
      [ -z "$sofile" ] && continue
      echo
      echo "----- preload target: $sofile -----"
      ls -lah "$sofile" 2>/dev/null || true
      file "$sofile" 2>/dev/null || true
      sha256sum "$sofile" 2>/dev/null || true
      strings -a "$sofile" 2>/dev/null \
        | grep -Eia 'hide|proc|kill|ssh|curl|wget|miner|stratum|socket|connect|passwd|shadow|authorized|preload|readdir|open|exec|usranalyse' \
        | head -100 || true
    done < /etc/ld.so.preload

    host_high "/etc/ld.so.preload 存在且命中恶意特征"
  else
    host_warn "/etc/ld.so.preload 存在，但未命中当前恶意特征，需要人工确认"
  fi
else
  host_ok "/etc/ld.so.preload 不存在"
fi

section "5. 母机临时目录强特征文件"
HOST_TMP_STRONG="$(find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null | grep -Eia 'SystemLog|/tmp/b$|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|xmrig|kinsing|kdevtmpfsi|usranalyse' || true)"

if [ -n "$HOST_TMP_STRONG" ]; then
  echo "$HOST_TMP_STRONG"
  host_high "母机临时目录发现强特征恶意文件"
else
  host_ok "母机临时目录未发现强特征恶意文件"
fi

HOST_TMP_ALL="$(find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null || true)"
if [ -n "$HOST_TMP_ALL" ]; then
  echo
  echo "----- 母机临时目录所有可执行文件，仅供人工确认，不直接判定感染 -----"
  echo "$HOST_TMP_ALL"
else
  ok "母机临时目录未发现可执行文件"
fi

section "6. 母机 cron / systemd / 启动项强特征"

HOST_CRON_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/cron* /var/spool/cron* 2>/dev/null || true)"
if [ -n "$HOST_CRON_STRONG" ]; then
  echo "----- cron 强特征 -----"
  echo "$HOST_CRON_STRONG"
  host_high "母机 cron 中发现强感染特征"
else
  host_ok "母机 cron 未发现强感染特征"
fi

HOST_SYSD_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/systemd/system /lib/systemd/system 2>/dev/null || true)"
if [ -n "$HOST_SYSD_STRONG" ]; then
  echo
  echo "----- systemd 强特征 -----"
  echo "$HOST_SYSD_STRONG"
  host_high "母机 systemd 中发现强感染特征"
else
  host_ok "母机 systemd 未发现强感染特征"
fi

HOST_START_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/rc.local /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null || true)"
if [ -n "$HOST_START_STRONG" ]; then
  echo
  echo "----- 启动项强特征 -----"
  echo "$HOST_START_STRONG"
  host_high "母机启动项中发现强感染特征"
else
  host_ok "母机启动项未发现强感染特征"
fi

section "7. 母机用户与 SSH 后门检查"
echo "----- UID 0 用户 -----"
UID0="$(awk -F: '$3==0 {print}' /etc/passwd)"
echo "$UID0"

UID0_COUNT="$(echo "$UID0" | grep -c .)"
if [ "$UID0_COUNT" -gt 1 ]; then
  host_high "发现多个 UID 0 用户，严重后门风险"
else
  host_ok "UID 0 用户数量正常"
fi

echo
echo "----- root authorized_keys -----"
if [ -f /root/.ssh/authorized_keys ]; then
  ls -lah /root/.ssh/authorized_keys
  cat /root/.ssh/authorized_keys
  host_warn "root authorized_keys 存在，请确认公钥是否都是你自己的"
else
  host_ok "root authorized_keys 不存在"
fi

section "8. 母机 deleted 运行程序"
DELETED_FOUND=0

for p in /proc/[0-9]*; do
  [ -e "$p/exe" ] || continue
  link="$(readlink "$p/exe" 2>/dev/null)"
  echo "$link" | grep -q 'deleted' || continue

  DELETED_FOUND=1
  pid="${p#/proc/}"
  echo "PID=$pid"
  echo "EXE=$link"
  echo "CMD=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
  echo
done

if [ "$DELETED_FOUND" -eq 1 ]; then
  host_warn "发现 deleted 状态运行程序，可能是升级残留，也可能是恶意进程"
else
  host_ok "未发现 deleted 状态运行程序"
fi

section "9. 母机网络连接"
echo "----- 监听端口 -----"
ss -lntup 2>/dev/null || true

echo
echo "----- 母机可疑连接过滤 -----"
HOST_NET_SUSP="$(ss -tunp 2>/dev/null | grep -Eia 'xmrig|miner|SystemLog|/tmp|/dev/shm|/var/tmp|stratum|3333|4444|5555|7777|14444|usranalyse|86\.54\.82\.179|152\.42\.182\.35' || true)"
if [ -n "$HOST_NET_SUSP" ]; then
  echo "$HOST_NET_SUSP"
  host_warn "母机发现可疑网络连接或可疑端口"
else
  host_ok "母机未发现常见矿池/木马特征连接"
fi

section "10. Incus 高危配置检查"
if has_cmd incus; then
  echo "----- Incus 容器列表 -----"
  incus list 2>/dev/null || true

  echo
  echo "----- 高危配置过滤 -----"

  while IFS=, read -r cname cstatus; do
    [ -z "$cname" ] && continue

    echo
    echo "===== $cname [$cstatus] ====="

    CFG="$(incus config show "$cname" --expanded 2>/dev/null || true)"

    RISK_CFG="$(echo "$CFG" | grep -Eia 'security.privileged|security.nesting|raw.lxc|raw.idmap|source: /|docker.sock|unix.socket|/var/lib/incus|/var/snap/lxd|/var/lib/lxd|/root|/etc' || true)"

    if [ -n "$RISK_CFG" ]; then
      echo "$RISK_CFG"
    else
      ok "$cname 未发现明显高危配置"
    fi

    echo "$CFG" \
      | grep -Eia 'security.privileged: "true"|raw.lxc|raw.idmap|source: /$|source: /root|source: /etc|docker.sock|unix.socket|/var/lib/incus|/var/snap/lxd|/var/lib/lxd' >/dev/null

    if [ $? -eq 0 ]; then
      escape_risk "实例 $cname 存在特权/挂载/socket/raw 配置，容器逃逸风险较高"
    fi
  done < <(incus list -c ns --format csv 2>/dev/null)

else
  host_warn "未找到 incus 命令，跳过 Incus 配置检查"
fi

if [ "$SCAN_CONTAINER" -eq 1 ]; then
  section "11. 扫描所有运行中的小鸡，重点检查安装哪吒的小鸡"

  if ! has_cmd incus; then
    echo "未找到 incus，跳过小鸡扫描。"
  else
    while IFS=, read -r cname cstatus; do
      [ -z "$cname" ] && continue

      if [ "$cstatus" != "RUNNING" ]; then
        container_skipped "$cname" "$cstatus" "容器未运行"
        continue
      fi

      C_HIGH=0
      C_WARN=0
      C_REASON=""
      C_NEZHA="否"

      echo
      echo "================ 小鸡: $cname [$cstatus] ================"

      echo "----- 哪吒安装检测 -----"
      C_NEZHA_INFO="$(run_in_container "$cname" '
        {
          echo "[process]"
          ps auxww 2>/dev/null | grep -Eia "nezha-agent|/opt/nezha|nezha" | grep -v grep

          echo
          echo "[path]"
          find /opt /etc /usr/local/bin /usr/bin /root -maxdepth 5 \
            \( -iname "*nezha*" -o -iname "config*.yml" \) -ls 2>/dev/null | head -100

          echo
          echo "[systemd]"
          find /etc/systemd/system /lib/systemd/system -maxdepth 2 \
            -iname "*nezha*" -ls 2>/dev/null | head -50

          echo
          echo "[openrc]"
          find /etc/init.d /etc/runlevels -maxdepth 3 \
            -iname "*nezha*" -ls 2>/dev/null | head -50

          echo
          echo "[config]"
          find /opt/nezha /etc/nezha -maxdepth 4 -type f 2>/dev/null | head -80
        }
      ' || true)"

      echo "$C_NEZHA_INFO"

      echo "$C_NEZHA_INFO" | grep -Eia 'nezha-agent|/opt/nezha|/etc/nezha|nezha' >/dev/null
      if [ $? -eq 0 ]; then
        C_NEZHA="是"
        CONTAINER_NEZHA_COUNT=$((CONTAINER_NEZHA_COUNT + 1))
        NEZHA_LIST="${NEZHA_LIST}
[哪吒小鸡] ${cname}"
        warn "$cname 安装/运行了哪吒相关组件，将重点扫描"
      else
        ok "$cname 未发现哪吒组件"
      fi

      if [ "$NEZHA_ONLY" -eq 1 ] && [ "$C_NEZHA" != "是" ]; then
        container_skipped "$cname" "$cstatus" "未安装哪吒，--nezha-only 跳过"
        continue
      fi

      echo
      echo "----- 哪吒目录异常文件检查 -----"
      C_NEZHA_BAD="$(run_in_container "$cname" '
        {
          find /opt/nezha /etc/nezha -type f -perm -111 -ls 2>/dev/null
          find /opt/nezha /etc/nezha -type f 2>/dev/null \
            | grep -Eia "SystemLog|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|xmrig|miner|kinsing|kdevtmpfsi|recvp\.php"
          grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|86\.54\.82\.179|152\.42\.182\.35" /opt/nezha /etc/nezha 2>/dev/null | head -120
        }
      ' || true)"

      if [ -n "$C_NEZHA_BAD" ]; then
        echo "$C_NEZHA_BAD"
        C_HIGH=1
        C_REASON="${C_REASON} 哪吒目录异常"
      else
        ok "$cname 哪吒目录未发现异常文件"
      fi

      echo
      echo "----- 当前进程强特征扫描 -----"
      C_PS="$(run_in_container "$cname" \
        'ps auxww 2>/dev/null | grep -Eia "xmrig|miner|kinsing|kdevtmpfsi|SystemLog|/tmp/b|/tmp/SystemLog|/tmp/download.sh|download.sh|ice.sh|harvest.sh|xmrig.sh|stratum|masscan|zmap|pnscan|/dev/shm|/var/tmp|usranalyse|ld.so.preload|recvp.php|curl .*sh|wget .*sh|curl.*\|.*sh|wget.*\|.*sh|86\.54\.82\.179|152\.42\.182\.35|mkdir -p /root/.ssh|chmod 700 /root/.ssh|\{\}" | grep -v grep' || true)"

      if [ -n "$C_PS" ]; then
        echo "$C_PS"
        C_HIGH=1
        C_REASON="${C_REASON} 可疑进程"
      else
        ok "$cname 当前进程未发现强特征"
      fi

      echo
      echo "----- 乱码进程检测 -----"
      C_GARBLED="$(run_in_container "$cname" '
        {
          ps -eo pid,ppid,user,stat,comm,args 2>/dev/null || ps auxww 2>/dev/null || ps 2>/dev/null
        } | awk "NR==1 {next} {print}" | grep -E "\?{3,}" | head -80
      ' || true)"

      if [ -n "$C_GARBLED" ]; then
        echo "$C_GARBLED"
        C_HIGH=1
        C_REASON="${C_REASON} 乱码进程"
        high "$cname 发现乱码进程，直接判定为疑似感染"
      else
        ok "$cname 未发现乱码进程"
      fi

      echo
      echo "----- 小鸡公网远端 IP / 连接数量检查，阈值 ${CONN_THRESHOLD} -----"
      C_CONN="$(run_in_container "$cname" '
        TMPF="/tmp/.nezhajc_conn_ips.$$"
        : > "$TMPF"

        if command -v ss >/dev/null 2>&1; then
          ss -Htun 2>/dev/null \
            | awk "{print \$5}" \
            | sed -E "s/^\[//; s/\].*$//; s/:[0-9*]+$//" \
            >> "$TMPF"
        elif command -v netstat >/dev/null 2>&1; then
          netstat -tun 2>/dev/null \
            | awk "NR>2{print \$5}" \
            | sed -E "s/^\[//; s/\].*$//; s/:[0-9*]+$//" \
            >> "$TMPF"
        else
          echo "NO_NET_TOOL=1"
          rm -f "$TMPF"
          exit 0
        fi

        grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" "$TMPF" \
          | grep -Ev "^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" \
          > "${TMPF}.pub"

        TOTAL_PUBLIC_CONN=$(wc -l < "${TMPF}.pub" 2>/dev/null | tr -d " ")
        UNIQUE_PUBLIC_IP=$(sort -u "${TMPF}.pub" 2>/dev/null | wc -l | tr -d " ")

        echo "TOTAL_PUBLIC_CONN=${TOTAL_PUBLIC_CONN:-0}"
        echo "UNIQUE_PUBLIC_IP=${UNIQUE_PUBLIC_IP:-0}"

        echo "TOP_REMOTE_IPS:"
        sort "${TMPF}.pub" 2>/dev/null | uniq -c | sort -nr | head -20

        rm -f "$TMPF" "${TMPF}.pub"
      ' || true)"

      echo "$C_CONN"

      if echo "$C_CONN" | grep -q "NO_NET_TOOL=1"; then
        C_WARN=1
        C_REASON="${C_REASON} 缺少网络检测工具"
        warn "$cname 缺少 ss/netstat，无法统计连接数量"
      else
        TOTAL_PUBLIC_CONN="$(echo "$C_CONN" | awk -F= '/TOTAL_PUBLIC_CONN=/{print $2}' | tail -1)"
        UNIQUE_PUBLIC_IP="$(echo "$C_CONN" | awk -F= '/UNIQUE_PUBLIC_IP=/{print $2}' | tail -1)"

        TOTAL_PUBLIC_CONN="${TOTAL_PUBLIC_CONN:-0}"
        UNIQUE_PUBLIC_IP="${UNIQUE_PUBLIC_IP:-0}"

        if [ "$UNIQUE_PUBLIC_IP" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
          C_HIGH=1
          C_REASON="${C_REASON} 公网远端IP过多_${UNIQUE_PUBLIC_IP}"
          high "$cname 公网远端 IP 数 ${UNIQUE_PUBLIC_IP} >= ${CONN_THRESHOLD}"
        elif [ "$TOTAL_PUBLIC_CONN" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
          C_HIGH=1
          C_REASON="${C_REASON} 公网连接过多_${TOTAL_PUBLIC_CONN}"
          high "$cname 公网连接数 ${TOTAL_PUBLIC_CONN} >= ${CONN_THRESHOLD}"
        else
          ok "$cname 公网远端 IP / 连接数量未超过阈值"
        fi
      fi

      echo
      echo "----- /etc/ld.so.preload -----"
      C_PRELOAD="$(run_in_container "$cname" \
        'if [ -s /etc/ld.so.preload ]; then ls -lah /etc/ld.so.preload; cat /etc/ld.so.preload; fi' || true)"

      if [ -n "$C_PRELOAD" ]; then
        echo "$C_PRELOAD"
        echo "$C_PRELOAD" | grep -Eia 'usranalyse|libusranalyse|xmrig|miner|SystemLog|/tmp|/dev/shm|/var/tmp' >/dev/null
        if [ $? -eq 0 ]; then
          C_HIGH=1
          C_REASON="${C_REASON} ld.so.preload异常"
        else
          C_WARN=1
          C_REASON="${C_REASON} preload存在"
        fi
      else
        ok "$cname /etc/ld.so.preload 不存在"
      fi

      echo
      echo "----- 临时目录可执行文件 -----"
      C_TMP="$(run_in_container "$cname" \
        'find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null | head -200' || true)"

      if [ -n "$C_TMP" ]; then
        echo "$C_TMP"

        echo "$C_TMP" | grep -Eia 'SystemLog|/tmp/b|download.sh|ice.sh|harvest.sh|xmrig.sh|xmrig|miner|kinsing|kdevtmpfsi|usranalyse|stratum' >/dev/null
        if [ $? -eq 0 ]; then
          C_HIGH=1
          C_REASON="${C_REASON} 临时目录恶意文件"
        else
          C_WARN=1
          C_REASON="${C_REASON} 临时目录可执行文件"
        fi
      else
        ok "$cname 临时目录未发现可执行文件"
      fi

      echo
      echo "----- cron 可疑项 -----"
      C_CRON="$(run_in_container "$cname" \
        '{
          crontab -l 2>/dev/null
          grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/cron* /etc/crontabs /etc/periodic /var/spool/cron* 2>/dev/null
        } | head -200' || true)"

      if [ -n "$C_CRON" ]; then
        echo "$C_CRON"
        C_HIGH=1
        C_REASON="${C_REASON} cron可疑"
      else
        ok "$cname cron 未发现可疑项"
      fi

      echo
      echo "----- 启动项可疑项 systemd/openrc/profile -----"
      C_STARTUP="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/systemd/system /lib/systemd/system /etc/init.d /etc/runlevels /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null | head -200' || true)"

      if [ -n "$C_STARTUP" ]; then
        echo "$C_STARTUP"
        C_HIGH=1
        C_REASON="${C_REASON} 启动项可疑"
      else
        ok "$cname 启动项未发现可疑项"
      fi

      echo
      echo "----- SSH authorized_keys 检查，仅提示 -----"
      C_SSH="$(run_in_container "$cname" \
        '{
          if [ -f /root/.ssh/authorized_keys ]; then
            echo "[root authorized_keys]"
            ls -lah /root/.ssh/authorized_keys
            cat /root/.ssh/authorized_keys
          fi
          find /root/.ssh /home -name authorized_keys -type f -ls 2>/dev/null
        } | head -200' || true)"

      if [ -n "$C_SSH" ]; then
        echo "$C_SSH"
        C_WARN=1
        C_REASON="${C_REASON} SSH公钥需确认"
      else
        ok "$cname 未发现 authorized_keys"
      fi

      echo
      echo "----- 历史命令可疑项，仅提示 -----"
      C_HISTORY="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|86\.54\.82\.179|152\.42\.182\.35" /root/.bash_history /home/*/.bash_history 2>/dev/null | head -120' || true)"

      if [ -n "$C_HISTORY" ]; then
        echo "$C_HISTORY"
        C_WARN=1
        C_REASON="${C_REASON} 历史命令可疑"
      else
        ok "$cname 历史命令未发现可疑项"
      fi

      if [ "$C_HIGH" -eq 1 ]; then
        container_infected "$cname" "$C_REASON" "$C_NEZHA"
      elif [ "$C_WARN" -eq 1 ]; then
        container_warn "$cname" "$C_REASON" "$C_NEZHA"
      else
        ok "$cname | 哪吒:${C_NEZHA} | 未发现明显感染痕迹"
      fi

    done < <(incus list -c ns --format csv 2>/dev/null)
  fi
else
  section "11. 小鸡扫描"
  echo "已使用 --host-only，跳过小鸡扫描。"
fi

section "12. 最终结论"
echo "报告文件：$REPORT"
echo

if [ "$HOST_HIGH" -eq 1 ]; then
  echo -e "${RED}母机感染状态：疑似感染 / 高危${NC}"
elif [ "$HOST_WARN" -eq 1 ]; then
  echo -e "${YELLOW}母机感染状态：未发现明确感染，但存在可疑项，需要人工确认${NC}"
else
  echo -e "${GREEN}母机感染状态：未发现明显感染痕迹${NC}"
fi

if [ "$ESCAPE_RISK" -eq 1 ]; then
  echo -e "${RED}容器逃逸风险配置：发现高危配置，需要检查对应实例${NC}"
else
  echo -e "${GREEN}容器逃逸风险配置：未发现明显高危配置${NC}"
fi

echo
echo "安装/运行哪吒的小鸡数量：$CONTAINER_NEZHA_COUNT"
if [ "$CONTAINER_NEZHA_COUNT" -gt 0 ]; then
  echo "$NEZHA_LIST"
else
  echo -e "${GREEN}未发现安装/运行哪吒的小鸡${NC}"
fi

echo
echo "哪吒小鸡疑似感染数量：$CONTAINER_NEZHA_INFECTED_COUNT"
if [ "$CONTAINER_NEZHA_INFECTED_COUNT" -gt 0 ]; then
  echo -e "${RED}${NEZHA_INFECTED_LIST}${NC}"
else
  echo -e "${GREEN}未发现哪吒小鸡疑似感染${NC}"
fi

echo
echo "全部疑似感染小鸡数量：$CONTAINER_INFECTED_COUNT"
if [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  echo -e "${RED}${INFECTED_LIST}${NC}"
else
  echo -e "${GREEN}未发现疑似感染小鸡${NC}"
fi

echo
echo "可疑小鸡数量：$CONTAINER_WARN_COUNT"
if [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  echo -e "${YELLOW}${WARN_LIST}${NC}"
else
  echo -e "${GREEN}未发现仅 WARN 的小鸡${NC}"
fi

echo
echo "未扫描小鸡数量：$CONTAINER_SKIPPED_COUNT"
if [ "$CONTAINER_SKIPPED_COUNT" -gt 0 ]; then
  echo "$SKIPPED_LIST"
fi

echo
echo "判定规则："
echo "1. 母机不会因为容器映射用户 1000000 出现可疑进程就直接判定感染。"
echo "2. 母机只有命中 root 强特征进程、恶意 ld.so.preload、母机临时目录强特征文件、母机 cron/systemd 强特征时才判定高危。"
echo "3. 小鸡安装/运行哪吒会显示为 [哪吒小鸡]，并重点扫描哪吒目录、哪吒服务、哪吒进程、哪吒配置。"
echo "4. 小鸡公网远端 IP 数或公网连接数 >= ${CONN_THRESHOLD} 时，直接标记为疑似感染。"
echo "5. 小鸡出现 /tmp/SystemLog、/tmp/b、download.sh、ice.sh、harvest.sh、xmrig.sh、ld.so.preload、可疑 cron、下载执行命令，直接标记为疑似感染。"
echo "6. 小鸡内部只要发现乱码进程，例如 ???、????、??????，直接标记为疑似感染。"
echo "7. authorized_keys 和历史命令默认只标记 WARN，需要人工确认。"
echo "8. 使用 --nezha-only 可以只扫描安装/运行哪吒的小鸡。"
echo "9. 没有脚本能 100% 证明系统绝对干净。"

if [ "$HOST_HIGH" -eq 1 ] || [ "$ESCAPE_RISK" -eq 1 ] || [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  exit 2
elif [ "$HOST_WARN" -eq 1 ] || [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  exit 1
else
  exit 0
fi
