#!/usr/bin/env bash
# nezhajc.sh
# 母机 + Incus/LXC 小鸡感染痕迹检测脚本
# 只读检测：不删除、不杀进程、不修改配置
#
# 用法：
#   bash nezhajc.sh
#   bash nezhajc.sh --host-only
#   bash nezhajc.sh --no-color
#
# 退出码：
#   0 = 未发现明显感染痕迹
#   1 = 存在 WARN 可疑项
#   2 = 存在 HIGH 感染/高危项

set +e
export LC_ALL=C

SCAN_CONTAINER=1
USE_COLOR=1

for arg in "$@"; do
  case "$arg" in
    --host-only|--no-container)
      SCAN_CONTAINER=0
      ;;
    --no-color)
      USE_COLOR=0
      ;;
    -h|--help)
      cat <<'HELP'
Usage:
  bash nezhajc.sh
  bash nezhajc.sh --host-only
  bash nezhajc.sh --no-color

Description:
  Read-only security check for Incus/LXC host and containers.

Exit code:
  0 = no obvious signs
  1 = warning signs found
  2 = high-risk infection signs found
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

INFECTED_LIST=""
WARN_LIST=""
SKIPPED_LIST=""

# 强感染特征：命中后一般直接判 INFECTED/HIGH
STRONG_RE='xmrig|kinsing|kdevtmpfsi|SystemLog|/tmp/SystemLog|/tmp/b([[:space:]]|$)|/tmp/download\.sh|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|stratum|masscan|zmap|pnscan|libusranalyse|usranalyse|ld\.so\.preload|recvp\.php|/root/\.ssh|authorized_keys|mkdir -p /root/\.ssh|chmod 700 /root/\.ssh'

# 普通可疑特征：命中后 WARN，若结合上下文可转 HIGH
SUSP_RE='xmrig|miner|kinsing|kdevtmpfsi|SystemLog|/tmp/SystemLog|/tmp/b([[:space:]]|$)|/tmp/download\.sh|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|stratum|masscan|zmap|pnscan|/dev/shm|/var/tmp|ld\.so\.preload|usranalyse|libusranalyse|recvp\.php|base64 -d|curl .*sh|wget .*sh|curl.*\|.*sh|wget.*\|.*sh|bash -c|sh -c|chmod \+x|chattr|authorized_keys|/root/\.ssh|mkdir -p /root/\.ssh|^[[:space:]]*[0-9]+[[:space:]]+.*\{\}'

# URL/IP 下载执行特征
URL_EXEC_RE='http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|curl -fsSL|curl -sL|curl -s |wget -O-|wget -qO-|wget .* -O /tmp|curl .* -o /tmp'

section() {
  echo
  echo -e "${BLUE}================ $* ================${NC}"
}

host_high() {
  HOST_HIGH=1
  echo -e "${RED}[HOST-HIGH] $*${NC}"
}

host_warn() {
  HOST_WARN=1
  echo -e "${YELLOW}[HOST-WARN] $*${NC}"
}

host_ok() {
  echo -e "${GREEN}[HOST-OK] $*${NC}"
}

escape_risk() {
  ESCAPE_RISK=1
  echo -e "${RED}[ESCAPE-RISK] $*${NC}"
}

container_infected() {
  local name="$1"
  local reason="$2"

  CONTAINER_INFECTED_COUNT=$((CONTAINER_INFECTED_COUNT + 1))
  INFECTED_LIST="${INFECTED_LIST}
[INFECTED] ${name} | 原因:${reason}"
  echo -e "${RED}[CONTAINER-INFECTED] ${name} | 原因:${reason}${NC}"
}

container_warn() {
  local name="$1"
  local reason="$2"

  CONTAINER_WARN_COUNT=$((CONTAINER_WARN_COUNT + 1))
  WARN_LIST="${WARN_LIST}
[WARN] ${name} | 原因:${reason}"
  echo -e "${YELLOW}[CONTAINER-WARN] ${name} | 原因:${reason}${NC}"
}

container_skipped() {
  local name="$1"
  local status="$2"

  CONTAINER_SKIPPED_COUNT=$((CONTAINER_SKIPPED_COUNT + 1))
  SKIPPED_LIST="${SKIPPED_LIST}
[SKIPPED] ${name} | 状态:${status}"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_in_container() {
  local cname="$1"
  local cmd="$2"

  if has_cmd timeout; then
    timeout 25 incus exec "$cname" -- sh -c "$cmd" 2>/dev/null
  else
    incus exec "$cname" -- sh -c "$cmd" 2>/dev/null
  fi
}

print_suspicious_block() {
  local title="$1"
  local content="$2"

  if [ -n "$content" ]; then
    echo
    echo -e "${YELLOW}----- ${title} -----${NC}"
    echo "$content"
  fi
}

section "0. 基础信息"
echo "报告文件: $REPORT"
echo "主机名:   $HOST"
echo "时间:     $(date)"
echo "内核:     $(uname -a)"
echo "用户:     $(id)"
echo

echo "虚拟化环境:"
systemd-detect-virt 2>/dev/null || true
echo

echo "负载:"
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
echo "----- MEM TOP 30 -----"
ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --sort=-pmem | head -30

section "2. 母机可疑进程扫描"
HOST_PS="$(ps auxww | grep -Eia "$SUSP_RE|$URL_EXEC_RE" | grep -vE 'grep|nezhajc|muji_infection_check' || true)"

if [ -n "$HOST_PS" ]; then
  echo "$HOST_PS"

  echo "$HOST_PS" | awk '$1=="root"{print}' | grep -Eia "$STRONG_RE|$URL_EXEC_RE" >/dev/null
  if [ $? -eq 0 ]; then
    host_high "母机 root 身份存在强特征可疑进程"
  else
    host_warn "发现可疑关键词进程；若 USER 为 1000000，多数是容器映射进程"
  fi
else
  host_ok "未发现常见挖矿/木马关键词进程"
fi

section "3. 母机 /etc/ld.so.preload 检查"
if [ -e /etc/ld.so.preload ]; then
  ls -lah /etc/ld.so.preload 2>/dev/null
  lsattr /etc/ld.so.preload 2>/dev/null || true

  echo "----- 内容 -----"
  cat /etc/ld.so.preload 2>/dev/null
  echo

  while read -r sofile; do
    [ -z "$sofile" ] && continue

    echo "----- preload target: $sofile -----"
    ls -lah "$sofile" 2>/dev/null || true
    file "$sofile" 2>/dev/null || true
    sha256sum "$sofile" 2>/dev/null || true

    strings -a "$sofile" 2>/dev/null \
      | grep -Eia 'hide|proc|kill|ssh|curl|wget|miner|stratum|socket|connect|passwd|shadow|authorized|preload|readdir|open|exec|usranalyse' \
      | head -100 || true
  done < /etc/ld.so.preload

  host_high "/etc/ld.so.preload 存在，这是 Rootkit/动态库劫持常见位置"
else
  host_ok "/etc/ld.so.preload 不存在"
fi

section "4. 母机临时目录可执行文件"
TMP_EXEC="$(find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null || true)"

if [ -n "$TMP_EXEC" ]; then
  echo "$TMP_EXEC"

  echo "$TMP_EXEC" | grep -Eia "$STRONG_RE" >/dev/null
  if [ $? -eq 0 ]; then
    host_high "母机临时目录发现强特征可疑可执行文件"
  else
    host_warn "母机临时目录存在可执行文件，需要人工确认"
  fi
else
  host_ok "母机 /tmp /var/tmp /dev/shm 未发现可执行文件"
fi

section "5. 母机 deleted 运行程序"
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

section "6. 母机网络连接"
echo "----- 监听端口 -----"
ss -lntup 2>/dev/null || true

echo
echo "----- 可疑连接过滤 -----"
NET_SUSP="$(ss -tunp 2>/dev/null | grep -Eia 'xmrig|miner|SystemLog|/tmp|/dev/shm|/var/tmp|stratum|3333|4444|5555|7777|14444|usranalyse|86\.54\.82\.179|152\.42\.182\.35' || true)"

if [ -n "$NET_SUSP" ]; then
  echo "$NET_SUSP"
  host_warn "发现可疑网络连接或可疑端口"
else
  host_ok "未发现常见矿池/木马特征连接"
fi

section "7. 母机 cron 检查"
echo "----- root crontab -----"
ROOT_CRON="$(crontab -l 2>/dev/null || true)"
echo "$ROOT_CRON"

echo
echo "----- 可疑 cron grep -----"
CRON_SUSP="$(grep -RInE "$SUSP_RE|$URL_EXEC_RE" /etc/cron* /var/spool/cron* 2>/dev/null || true)"

if [ -n "$CRON_SUSP" ]; then
  echo "$CRON_SUSP"

  echo "$CRON_SUSP" | grep -Eia "$STRONG_RE|$URL_EXEC_RE" >/dev/null
  if [ $? -eq 0 ]; then
    host_high "cron 中存在强特征可疑项"
  else
    host_warn "cron 中存在可疑关键词，需要人工确认"
  fi
else
  host_ok "cron 未发现常见恶意关键词"
fi

section "8. 母机 systemd 检查"
echo "----- 最近 10 天修改的 systemd 文件 -----"
find /etc/systemd/system /lib/systemd/system -type f -mtime -10 -ls 2>/dev/null | head -200 || true

echo
echo "----- 可疑 systemd grep -----"
SYSD_SUSP="$(grep -RInE "$SUSP_RE|$URL_EXEC_RE" /etc/systemd/system /lib/systemd/system 2>/dev/null || true)"

if [ -n "$SYSD_SUSP" ]; then
  echo "$SYSD_SUSP"

  echo "$SYSD_SUSP" | grep -Eia "$STRONG_RE|$URL_EXEC_RE" >/dev/null
  if [ $? -eq 0 ]; then
    host_high "systemd 中存在强特征可疑项"
  else
    host_warn "systemd 中存在可疑关键词，需要人工确认"
  fi
else
  host_ok "systemd 未发现常见恶意关键词"
fi

section "9. 母机 profile / shell 启动项检查"
STARTUP_SUSP="$(grep -RInE "$SUSP_RE|$URL_EXEC_RE" \
  /etc/rc.local \
  /etc/profile \
  /etc/profile.d \
  /root/.bashrc \
  /root/.profile \
  /root/.ssh \
  2>/dev/null || true)"

if [ -n "$STARTUP_SUSP" ]; then
  echo "$STARTUP_SUSP"

  echo "$STARTUP_SUSP" | grep -Eia "$STRONG_RE|$URL_EXEC_RE" >/dev/null
  if [ $? -eq 0 ]; then
    host_high "profile/shell 启动项中存在强特征可疑项"
  else
    host_warn "profile/shell 启动项中存在可疑关键词"
  fi
else
  host_ok "profile/shell 启动项未发现常见恶意关键词"
fi

section "10. 母机用户与 SSH 后门检查"
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

section "11. SSH 登录记录"
echo "----- 当前登录 -----"
who 2>/dev/null || true
w 2>/dev/null || true

echo
echo "----- 最近登录 -----"
last -a | head -50 2>/dev/null || true

echo
echo "----- SSH 最近 24 小时日志 -----"
journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | tail -120 || \
journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | tail -120 || true

section "12. Incus 高危配置检查"
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

    echo "$CFG" \
      | grep -Eia 'security.privileged|security.nesting|raw.lxc|raw.idmap|source: /|docker.sock|unix.socket|/var/lib/incus|/var/snap/lxd|/var/lib/lxd|/root|/etc' || true

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
  section "13. 扫描所有运行中的小鸡感染痕迹"

  if ! has_cmd incus; then
    echo "未找到 incus，跳过小鸡扫描。"
  else
    while IFS=, read -r cname cstatus; do
      [ -z "$cname" ] && continue

      if [ "$cstatus" != "RUNNING" ]; then
        container_skipped "$cname" "$cstatus"
        continue
      fi

      C_HIGH=0
      C_WARN=0
      C_REASON=""

      echo
      echo "================ 小鸡: $cname [$cstatus] ================"

      echo "----- 进程强特征扫描 -----"
      C_PS="$(run_in_container "$cname" \
        'ps -efww 2>/dev/null | grep -Eia "xmrig|miner|kinsing|kdevtmpfsi|SystemLog|/tmp/b|/tmp/SystemLog|/tmp/download.sh|download.sh|ice.sh|harvest.sh|xmrig.sh|stratum|masscan|zmap|pnscan|/dev/shm|/var/tmp|usranalyse|ld.so.preload|recvp.php|authorized_keys|/root/.ssh|curl .*sh|wget .*sh|curl.*\|.*sh|wget.*\|.*sh|86\.54\.82\.179|152\.42\.182\.35|mkdir -p /root/.ssh|chmod 700 /root/.ssh|\{\}" | grep -v grep' || true)"

      if [ -n "$C_PS" ]; then
        echo "$C_PS"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_process"
      else
        echo "未发现"
      fi

      echo
      echo "----- 可疑下载执行命令扫描 -----"
      C_URL_EXEC="$(run_in_container "$cname" \
        'ps -efww 2>/dev/null | grep -Eia "http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|curl -fsSL|curl -sL|wget -O-|wget -qO-|curl .* -o /tmp|wget .* -O /tmp|ice.sh|harvest.sh|xmrig.sh|recvp.php" | grep -v grep' || true)"

      if [ -n "$C_URL_EXEC" ]; then
        echo "$C_URL_EXEC"
        C_HIGH=1
        C_REASON="${C_REASON} download_exec"
      else
        echo "未发现"
      fi

      echo
      echo "----- /etc/ld.so.preload -----"
      C_PRELOAD="$(run_in_container "$cname" \
        'if [ -s /etc/ld.so.preload ]; then ls -lah /etc/ld.so.preload; cat /etc/ld.so.preload; fi' || true)"

      if [ -n "$C_PRELOAD" ]; then
        echo "$C_PRELOAD"
        C_HIGH=1
        C_REASON="${C_REASON} ld.so.preload"
      else
        echo "不存在"
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
          C_REASON="${C_REASON} tmp_strong_exec"
        else
          C_WARN=1
          C_REASON="${C_REASON} tmp_exec"
        fi
      else
        echo "未发现"
      fi

      echo
      echo "----- cron 可疑项 -----"
      C_CRON="$(run_in_container "$cname" \
        '{
          crontab -l 2>/dev/null
          grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|authorized_keys|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/cron* /etc/crontabs /etc/periodic /var/spool/cron* 2>/dev/null
        } | head -200' || true)"

      if [ -n "$C_CRON" ]; then
        echo "$C_CRON"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_cron"
      else
        echo "未发现"
      fi

      echo
      echo "----- 启动项可疑项 systemd/openrc/profile -----"
      C_STARTUP="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|authorized_keys|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/systemd/system /lib/systemd/system /etc/init.d /etc/runlevels /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null | head -200' || true)"

      if [ -n "$C_STARTUP" ]; then
        echo "$C_STARTUP"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_startup"
      else
        echo "未发现"
      fi

      echo
      echo "----- SSH 后门与 authorized_keys 检查 -----"
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
        C_REASON="${C_REASON} ssh_key_check"
      else
        echo "未发现 authorized_keys"
      fi

      echo
      echo "----- 可疑历史命令检查 -----"
      C_HISTORY="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|authorized_keys|86\.54\.82\.179|152\.42\.182\.35" /root/.bash_history /home/*/.bash_history 2>/dev/null | head -120' || true)"

      if [ -n "$C_HISTORY" ]; then
        echo "$C_HISTORY"
        C_WARN=1
        C_REASON="${C_REASON} suspicious_history"
      else
        echo "未发现"
      fi

      if [ "$C_HIGH" -eq 1 ]; then
        container_infected "$cname" "$C_REASON"
      elif [ "$C_WARN" -eq 1 ]; then
        container_warn "$cname" "$C_REASON"
      else
        echo -e "${GREEN}[CONTAINER-OK] $cname 未发现明显感染痕迹${NC}"
      fi

    done < <(incus list -c ns --format csv 2>/dev/null)
  fi
else
  section "13. 小鸡扫描"
  echo "已使用 --host-only，跳过小鸡扫描。"
fi

section "14. 最终结论"
echo "报告文件: $REPORT"
echo

if [ "$HOST_HIGH" -eq 1 ]; then
  echo -e "${RED}母机感染痕迹：疑似感染 / 高危${NC}"
elif [ "$HOST_WARN" -eq 1 ]; then
  echo -e "${YELLOW}母机感染痕迹：未发现明确感染，但存在可疑项，需要人工确认${NC}"
else
  echo -e "${GREEN}母机感染痕迹：未发现明显感染痕迹${NC}"
fi

if [ "$ESCAPE_RISK" -eq 1 ]; then
  echo -e "${RED}容器逃逸风险配置：发现高危配置，需要检查对应实例${NC}"
else
  echo -e "${GREEN}容器逃逸风险配置：未发现明显高危配置${NC}"
fi

echo
echo "疑似感染小鸡数量: $CONTAINER_INFECTED_COUNT"
if [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  echo -e "${RED}${INFECTED_LIST}${NC}"
else
  echo -e "${GREEN}未发现疑似感染小鸡${NC}"
fi

echo
echo "可疑小鸡数量: $CONTAINER_WARN_COUNT"
if [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  echo -e "${YELLOW}${WARN_LIST}${NC}"
else
  echo -e "${GREEN}未发现仅 WARN 的小鸡${NC}"
fi

echo
echo "未扫描小鸡数量: $CONTAINER_SKIPPED_COUNT"
if [ "$CONTAINER_SKIPPED_COUNT" -gt 0 ]; then
  echo "$SKIPPED_LIST"
fi

echo
echo "说明："
echo "1. [INFECTED] 表示发现强特征：如 /tmp/SystemLog、/tmp/b、download.sh、ice.sh、harvest.sh、xmrig.sh、ld.so.preload、可疑 cron、挖矿关键词、下载执行命令等。"
echo "2. [WARN] 表示存在可疑但不一定恶意的现象，如临时目录可执行文件、authorized_keys、历史命令可疑。"
echo "3. 如果小鸡出现 wget/curl 下载远程 sh 并 pipe 到 sh，基本可按已感染处理。"
echo "4. 如果母机出现 ld.so.preload、陌生 UID 0、root 可疑进程，建议重装母机。"
echo "5. 若小鸡出现 [INFECTED]，建议停机、备份必要业务数据、销毁重建。"

if [ "$HOST_HIGH" -eq 1 ] || [ "$ESCAPE_RISK" -eq 1 ] || [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  exit 2
elif [ "$HOST_WARN" -eq 1 ] || [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  exit 1
else
  exit 0
fi
