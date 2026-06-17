#!/usr/bin/env bash
# nezhajc1.sh
# Incus/LXC 小鸡哪吒 agent 被黑专项检测脚本
# 只读检测：不删除、不杀进程、不修改配置
#
# 检测重点：
#   1. 重点检查安装/运行哪吒 agent 的小鸡
#   2. 只检查本次哪吒被黑相关强特征
#   3. 乱码进程直接判疑似感染
#   4. 多台感染小鸡会全部显示
#   5. 普通 cron、普通启动项、普通 /tmp、普通 curl/wget、普通 authorized_keys 不直接判感染
#
# 用法：
#   bash nezhajc1.sh
#   bash nezhajc1.sh --nezha-only
#   bash nezhajc1.sh --quiet-ok
#   bash nezhajc1.sh --no-color
#
# 环境变量：
#   CONN_THRESHOLD=1000 bash nezhajc1.sh
#
# 退出码：
#   0 = 未发现明显感染痕迹
#   1 = 存在可疑项
#   2 = 存在疑似感染小鸡

set +e
export LC_ALL=C

NEZHA_ONLY=0
SHOW_OK=1
USE_COLOR=1
CONN_THRESHOLD="${CONN_THRESHOLD:-1000}"

for arg in "$@"; do
  case "$arg" in
    --nezha-only)
      NEZHA_ONLY=1
      ;;
    --quiet-ok)
      SHOW_OK=0
      ;;
    --show-ok)
      SHOW_OK=1
      ;;
    --no-color)
      USE_COLOR=0
      ;;
    -h|--help)
      cat <<HELP
用法：
  bash nezhajc1.sh
  bash nezhajc1.sh --nezha-only
  bash nezhajc1.sh --quiet-ok
  bash nezhajc1.sh --no-color

参数：
  --nezha-only   只扫描安装/运行哪吒 agent 的小鸡
  --quiet-ok     不显示正常小鸡的绿色 OK 过程
  --show-ok      显示正常小鸡的绿色 OK 过程，默认开启
  --no-color     关闭颜色输出

环境变量：
  CONN_THRESHOLD=1000 bash nezhajc1.sh

退出码：
  0 = 未发现明显感染痕迹
  1 = 存在可疑项
  2 = 存在疑似感染小鸡
HELP
      exit 0
      ;;
  esac
done

HOST="$(hostname 2>/dev/null || echo unknown)"
TIME="$(date +%F-%H%M%S)"
REPORT="/root/nezhajc1_${HOST}_${TIME}.log"

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

TOTAL_COUNT=0
RUNNING_COUNT=0
SKIPPED_COUNT=0
NEZHA_COUNT=0
INFECTED_COUNT=0
WARN_COUNT=0

NEZHA_LIST=""
INFECTED_LIST=""
WARN_LIST=""
SKIPPED_LIST=""
CONN_RANK_LIST=""

# 这次已知相关恶意 IP
KNOWN_IP_RE='86\.54\.82\.179|152\.42\.182\.35'

# 只针对已知强恶意文件名，不再匹配普通 /tmp、普通 sh、普通 curl/wget
MAL_FILE_RE='/(SystemLog|b|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|xmrig|kinsing|kdevtmpfsi|recvp\.php)([[:space:]]|$)'

# 强命令特征：
# 1. curl/wget 管道执行 sh/bash
# 2. /tmp/SystemLog、/tmp/b
# 3. download.sh、ice.sh、harvest.sh、xmrig.sh
# 4. xmrig、stratum+tcp、recvp.php
# 5. 写入 root authorized_keys 的后门行为
MAL_CMD_RE='(curl|wget).*\|[[:space:]]*(sh|bash)|/tmp/SystemLog|(^|[[:space:]])/tmp/b([[:space:]]|$)|(^|[[:space:]])/tmp/(download\.sh|ice\.sh|harvest\.sh|xmrig\.sh)([[:space:]]|$)|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|(^|[[:space:]])xmrig([[:space:]]|$)|stratum\+tcp|recvp\.php|(>>|>|tee).*authorized_keys'

section() {
  echo
  echo -e "${BLUE}================ $* ================${NC}"
}

ok() {
  if [ "$SHOW_OK" -eq 1 ]; then
    echo -e "${GREEN}[OK] $*${NC}"
  fi
}

warn() {
  echo -e "${YELLOW}[WARN] $*${NC}"
}

high() {
  echo -e "${RED}[HIGH] $*${NC}"
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

add_reason() {
  local r="$1"
  if [ -z "$C_REASON" ]; then
    C_REASON="$r"
  else
    C_REASON="${C_REASON}；${r}"
  fi
}

add_warn_reason() {
  local r="$1"
  if [ -z "$C_WARN_REASON" ]; then
    C_WARN_REASON="$r"
  else
    C_WARN_REASON="${C_WARN_REASON}；${r}"
  fi
}

mark_infected() {
  local cname="$1"
  local nezha="$2"
  local reason="$3"

  INFECTED_COUNT=$((INFECTED_COUNT + 1))
  INFECTED_LIST="${INFECTED_LIST}
[疑似感染] ${cname} | 哪吒:${nezha} | 原因:${reason}"

  high "小鸡疑似感染：${cname} | 哪吒:${nezha} | 原因:${reason}"
}

mark_warn() {
  local cname="$1"
  local nezha="$2"
  local reason="$3"

  WARN_COUNT=$((WARN_COUNT + 1))
  WARN_LIST="${WARN_LIST}
[可疑] ${cname} | 哪吒:${nezha} | 原因:${reason}"

  warn "小鸡存在可疑项：${cname} | 哪吒:${nezha} | 原因:${reason}"
}

mark_skipped() {
  local cname="$1"
  local status="$2"
  local reason="$3"

  SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
  SKIPPED_LIST="${SKIPPED_LIST}
[未扫描] ${cname} | 状态:${status} | 原因:${reason}"
}

section "0. 基础信息"
echo "报告文件：$REPORT"
echo "主机名：$HOST"
echo "时间：$(date)"
echo "公网连接阈值：${CONN_THRESHOLD}"
echo "只扫哪吒小鸡：${NEZHA_ONLY}"
echo "显示正常项：${SHOW_OK}"
echo

if [ "$(id -u)" != "0" ]; then
  warn "当前不是 root，检测结果可能不完整"
else
  ok "当前是 root，权限完整"
fi

if ! has_cmd incus; then
  high "未找到 incus 命令，无法扫描小鸡"
  exit 2
fi

section "1. Incus 小鸡列表"
incus list 2>/dev/null || true

section "2. 哪吒 agent 被黑专项扫描"

while IFS=, read -r cname cstatus; do
  [ -z "$cname" ] && continue

  TOTAL_COUNT=$((TOTAL_COUNT + 1))

  if [ "$cstatus" != "RUNNING" ]; then
    mark_skipped "$cname" "$cstatus" "小鸡未运行"
    continue
  fi

  RUNNING_COUNT=$((RUNNING_COUNT + 1))

  C_REASON=""
  C_WARN_REASON=""
  C_NEZHA="否"
  TOTAL_PUBLIC_CONN=0
  UNIQUE_PUBLIC_IP=0

  echo
  echo "---------- 扫描小鸡：$cname [$cstatus] ----------"

  echo "----- 哪吒 agent 安装/运行检测 -----"
  C_NEZHA_INFO="$(run_in_container "$cname" '
    {
      echo "[process]"
      ps auxww 2>/dev/null | grep -Eia "nezha-agent|/opt/nezha|/etc/nezha|nezha" | grep -v grep

      echo
      echo "[path]"
      find /opt /etc /usr/local/bin /usr/bin /root -maxdepth 5 \
        \( -iname "*nezha*" -o -iname "config*.yml" \) -ls 2>/dev/null | head -120

      echo
      echo "[service]"
      find /etc/systemd/system /lib/systemd/system /etc/init.d /etc/runlevels -maxdepth 4 \
        -iname "*nezha*" -ls 2>/dev/null | head -100

      echo
      echo "[agent-config]"
      find /opt/nezha /etc/nezha -maxdepth 5 -type f 2>/dev/null | head -120
    }
  ' || true)"

  echo "$C_NEZHA_INFO" | grep -Eia 'nezha-agent|/opt/nezha|/etc/nezha|nezha' >/dev/null
  if [ $? -eq 0 ]; then
    C_NEZHA="是"
    NEZHA_COUNT=$((NEZHA_COUNT + 1))
    NEZHA_LIST="${NEZHA_LIST}
[哪吒小鸡] ${cname}"
    warn "$cname 安装/运行了哪吒 agent，进入重点检查"
    echo "$C_NEZHA_INFO"
  else
    ok "$cname 未发现哪吒 agent"
    if [ "$NEZHA_ONLY" -eq 1 ]; then
      mark_skipped "$cname" "$cstatus" "未发现哪吒 agent，--nezha-only 跳过"
      continue
    fi
  fi

  echo
  echo "----- 乱码进程检测 -----"
  C_GARBLED="$(run_in_container "$cname" '
    {
      ps -eo pid,ppid,user,stat,comm,args 2>/dev/null || ps auxww 2>/dev/null || ps 2>/dev/null
    } | awk "NR==1 {next} {print}" \
      | grep -E "\?{3,}|(^|[[:space:]])\{\}([[:space:]]|$)" \
      | grep -vE "grep -E|nezhajc" \
      | head -80
  ' || true)"

  if [ -n "$C_GARBLED" ]; then
    echo "$C_GARBLED"
    add_reason "乱码进程"
  else
    ok "$cname 未发现乱码进程"
  fi

  echo
  echo "----- 当前进程：哪吒被黑强特征 -----"
  C_PROC_BAD="$(run_in_container "$cname" "
    ps auxww 2>/dev/null \
      | grep -Eia '${MAL_CMD_RE}|${KNOWN_IP_RE}' \
      | grep -vE 'grep|nezhajc' \
      | head -120
  " || true)"

  if [ -n "$C_PROC_BAD" ]; then
    echo "$C_PROC_BAD"
    add_reason "当前进程命中哪吒被黑强特征"
  else
    ok "$cname 当前进程未命中哪吒被黑强特征"
  fi

  echo
  echo "----- 临时目录：哪吒被黑相关恶意文件 -----"
  C_TMP_BAD="$(run_in_container "$cname" "
    find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null \
      | grep -Eia '${MAL_FILE_RE}' \
      | head -120
  " || true)"

  if [ -n "$C_TMP_BAD" ]; then
    echo "$C_TMP_BAD"
    add_reason "临时目录发现哪吒被黑相关文件"
  else
    ok "$cname 临时目录未发现哪吒被黑相关文件"
  fi

  echo
  echo "----- 哪吒目录：恶意脚本/IP/下载执行痕迹 -----"
  C_NEZHA_BAD="$(run_in_container "$cname" "
    {
      find /opt/nezha /etc/nezha -type f -ls 2>/dev/null
      grep -RInE '${MAL_CMD_RE}|${KNOWN_IP_RE}' /opt/nezha /etc/nezha 2>/dev/null
    } | head -180
  " || true)"

  if [ -n "$C_NEZHA_BAD" ]; then
    echo "$C_NEZHA_BAD"
    add_reason "哪吒目录命中被黑相关特征"
  else
    ok "$cname 哪吒目录未命中被黑相关特征"
  fi

  echo
  echo "----- cron：只检查哪吒被黑强特征 -----"
  C_CRON_BAD="$(run_in_container "$cname" "
    {
      crontab -l 2>/dev/null
      grep -RInE '${MAL_CMD_RE}|${KNOWN_IP_RE}' /etc/cron* /etc/crontabs /etc/periodic /var/spool/cron* 2>/dev/null
    } | head -180
  " || true)"

  if [ -n "$C_CRON_BAD" ]; then
    echo "$C_CRON_BAD"
    add_reason "cron 命中哪吒被黑强特征"
  else
    ok "$cname cron 未命中哪吒被黑强特征"
  fi

  echo
  echo "----- 启动项：只检查哪吒被黑强特征 -----"
  C_START_BAD="$(run_in_container "$cname" "
    grep -RInE '${MAL_CMD_RE}|${KNOWN_IP_RE}' \
      /etc/systemd/system /lib/systemd/system /etc/init.d /etc/runlevels \
      /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null \
      | head -180
  " || true)"

  if [ -n "$C_START_BAD" ]; then
    echo "$C_START_BAD"
    add_reason "启动项命中哪吒被黑强特征"
  else
    ok "$cname 启动项未命中哪吒被黑强特征"
  fi

  echo
  echo "----- /etc/ld.so.preload 检查 -----"
  C_PRELOAD_BAD="$(run_in_container "$cname" '
    if [ -s /etc/ld.so.preload ]; then
      echo "[/etc/ld.so.preload]"
      ls -lah /etc/ld.so.preload 2>/dev/null
      cat /etc/ld.so.preload 2>/dev/null
    fi
  ' || true)"

  if [ -n "$C_PRELOAD_BAD" ]; then
    echo "$C_PRELOAD_BAD"
    echo "$C_PRELOAD_BAD" | grep -Eia 'usranalyse|libusranalyse|xmrig|miner|SystemLog|/tmp/SystemLog|/tmp/b|/dev/shm|/var/tmp' >/dev/null
    if [ $? -eq 0 ]; then
      add_reason "ld.so.preload 命中恶意特征"
    else
      add_warn_reason "存在 ld.so.preload，需人工确认"
    fi
  else
    ok "$cname /etc/ld.so.preload 不存在"
  fi

  echo
  echo "----- 当前公网连接数量检查，阈值 ${CONN_THRESHOLD} -----"
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
    add_warn_reason "缺少 ss/netstat，无法统计连接"
  else
    TOTAL_PUBLIC_CONN="$(echo "$C_CONN" | awk -F= '/TOTAL_PUBLIC_CONN=/{print $2}' | tail -1)"
    UNIQUE_PUBLIC_IP="$(echo "$C_CONN" | awk -F= '/UNIQUE_PUBLIC_IP=/{print $2}' | tail -1)"

    TOTAL_PUBLIC_CONN="${TOTAL_PUBLIC_CONN:-0}"
    UNIQUE_PUBLIC_IP="${UNIQUE_PUBLIC_IP:-0}"

    CONN_RANK_LIST="${CONN_RANK_LIST}
[连接统计] ${cname} | 哪吒:${C_NEZHA} | 公网连接:${TOTAL_PUBLIC_CONN} | 公网远端IP:${UNIQUE_PUBLIC_IP}"

    if [ "$UNIQUE_PUBLIC_IP" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
      add_reason "公网远端 IP 过多_${UNIQUE_PUBLIC_IP}"
    elif [ "$TOTAL_PUBLIC_CONN" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
      add_reason "公网连接数过多_${TOTAL_PUBLIC_CONN}"
    else
      ok "$cname 公网连接数量未超过阈值"
    fi
  fi

  if [ -n "$C_REASON" ]; then
    mark_infected "$cname" "$C_NEZHA" "$C_REASON"
  elif [ -n "$C_WARN_REASON" ]; then
    mark_warn "$cname" "$C_NEZHA" "$C_WARN_REASON"
  else
    ok "$cname | 哪吒:${C_NEZHA} | 未发现哪吒被黑相关感染特征"
  fi

done < <(incus list -c ns --format csv 2>/dev/null)

section "3. 最终结论"
echo "报告文件：$REPORT"
echo

echo "小鸡总数：$TOTAL_COUNT"
echo "运行中小鸡数量：$RUNNING_COUNT"
echo "安装/运行哪吒 agent 的小鸡数量：$NEZHA_COUNT"
echo "疑似感染小鸡数量：$INFECTED_COUNT"
echo "可疑小鸡数量：$WARN_COUNT"
echo "未扫描小鸡数量：$SKIPPED_COUNT"

echo
echo "----- 哪吒小鸡列表 -----"
if [ "$NEZHA_COUNT" -gt 0 ]; then
  echo "$NEZHA_LIST"
else
  ok "未发现安装/运行哪吒 agent 的小鸡"
fi

echo
echo "----- 疑似感染小鸡列表 -----"
if [ "$INFECTED_COUNT" -gt 0 ]; then
  echo -e "${RED}${INFECTED_LIST}${NC}"
else
  ok "未发现疑似感染小鸡"
fi

echo
echo "----- 可疑小鸡列表 -----"
if [ "$WARN_COUNT" -gt 0 ]; then
  echo -e "${YELLOW}${WARN_LIST}${NC}"
else
  ok "未发现仅可疑的小鸡"
fi

echo
echo "----- 未扫描小鸡列表 -----"
if [ "$SKIPPED_COUNT" -gt 0 ]; then
  echo "$SKIPPED_LIST"
else
  ok "没有未扫描小鸡"
fi

echo
echo "----- 小鸡公网连接统计 -----"
if [ -n "$CONN_RANK_LIST" ]; then
  echo "$CONN_RANK_LIST"
else
  ok "没有连接统计数据"
fi

echo
echo "判定规则："
echo "1. 本脚本只针对这次哪吒 agent 被黑相关强特征做专项检测。"
echo "2. 普通 cron、普通启动项、普通 /tmp、普通 curl/wget、普通 authorized_keys 不再直接判定感染。"
echo "3. 小鸡安装/运行哪吒 agent 会显示为 [哪吒小鸡]，并重点扫描哪吒目录、哪吒进程、哪吒配置。"
echo "4. 小鸡内部发现乱码进程，例如 ???、????、{}，直接标记为疑似感染。"
echo "5. 小鸡出现 /tmp/SystemLog、/tmp/b、download.sh、ice.sh、harvest.sh、xmrig.sh、recvp.php，直接标记为疑似感染。"
echo "6. 小鸡命中 86.54.82.179 或 152.42.182.35，直接标记为疑似感染。"
echo "7. cron 或启动项只有出现 curl/wget 管道执行 sh/bash、恶意脚本名、写入 authorized_keys 等强特征时，才标记为疑似感染。"
echo "8. 小鸡公网远端 IP 数或公网连接数 >= ${CONN_THRESHOLD} 时，直接标记为疑似感染。"
echo "9. 多台小鸡感染会在“疑似感染小鸡列表”中全部显示。"
echo "10. 使用 --nezha-only 可以只扫描安装/运行哪吒 agent 的小鸡。"
echo "11. 没有脚本能 100% 证明系统绝对干净。"

if [ "$INFECTED_COUNT" -gt 0 ]; then
  exit 2
elif [ "$WARN_COUNT" -gt 0 ]; then
  exit 1
else
  exit 0
fi
