#!/usr/bin/env bash
# nezhajc.sh
# Read-only security check for Incus/LXC host and containers.
# Focus:
#   1. Check containers with Nezha agent installed.
#   2. Mark container as INFECTED if public remote IP count or public connection count >= 1000.
#   3. Host is NOT marked infected only because container-mapped UID 1000000 has suspicious processes.
#
# Usage:
#   bash nezhajc.sh
#   bash nezhajc.sh --host-only
#   bash nezhajc.sh --nezha-only
#
# Env:
#   CONN_THRESHOLD=1000 bash nezhajc.sh
#
# Exit code:
#   0 = no obvious signs
#   1 = warnings found
#   2 = high-risk / infected signs found

set +e
export LC_ALL=C

SCAN_CONTAINER=1
NEZHA_ONLY=0
CONN_THRESHOLD="${CONN_THRESHOLD:-1000}"

for arg in "$@"; do
  case "$arg" in
    --host-only|--no-container)
      SCAN_CONTAINER=0
      ;;
    --nezha-only)
      NEZHA_ONLY=1
      ;;
    -h|--help)
      cat <<HELP
Usage:
  bash nezhajc.sh
  bash nezhajc.sh --host-only
  bash nezhajc.sh --nezha-only

Env:
  CONN_THRESHOLD=1000 bash nezhajc.sh

Exit code:
  0 = no obvious signs
  1 = warning signs found
  2 = high-risk or infected signs found
HELP
      exit 0
      ;;
  esac
done

HOST="$(hostname 2>/dev/null || echo unknown)"
TIME="$(date +%F-%H%M%S)"
REPORT="/root/nezhajc_${HOST}_${TIME}.log"

exec > >(tee -a "$REPORT") 2>&1

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
  echo "================ $* ================"
}

host_high() {
  HOST_HIGH=1
  echo "[HOST-HIGH] $*"
}

host_warn() {
  HOST_WARN=1
  echo "[HOST-WARN] $*"
}

host_ok() {
  echo "[HOST-OK] $*"
}

escape_risk() {
  ESCAPE_RISK=1
  echo "[ESCAPE-RISK] $*"
}

container_infected() {
  local name="$1"
  local reason="$2"
  local nezha_flag="$3"

  CONTAINER_INFECTED_COUNT=$((CONTAINER_INFECTED_COUNT + 1))
  INFECTED_LIST="${INFECTED_LIST}
[INFECTED] ${name} | NEZHA:${nezha_flag} | REASON:${reason}"

  if [ "$nezha_flag" = "YES" ]; then
    CONTAINER_NEZHA_INFECTED_COUNT=$((CONTAINER_NEZHA_INFECTED_COUNT + 1))
    NEZHA_INFECTED_LIST="${NEZHA_INFECTED_LIST}
[NEZHA-INFECTED] ${name} | REASON:${reason}"
  fi

  echo "[CONTAINER-INFECTED] ${name} | NEZHA:${nezha_flag} | REASON:${reason}"
}

container_warn() {
  local name="$1"
  local reason="$2"
  local nezha_flag="$3"

  CONTAINER_WARN_COUNT=$((CONTAINER_WARN_COUNT + 1))
  WARN_LIST="${WARN_LIST}
[WARN] ${name} | NEZHA:${nezha_flag} | REASON:${reason}"

  echo "[CONTAINER-WARN] ${name} | NEZHA:${nezha_flag} | REASON:${reason}"
}

container_skipped() {
  local name="$1"
  local status="$2"
  local reason="$3"

  CONTAINER_SKIPPED_COUNT=$((CONTAINER_SKIPPED_COUNT + 1))
  SKIPPED_LIST="${SKIPPED_LIST}
[SKIPPED] ${name} | STATUS:${status} | REASON:${reason}"
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

section "0. Basic Info"
echo "Report: $REPORT"
echo "Host:   $HOST"
echo "Time:   $(date)"
echo "Kernel: $(uname -a)"
echo "User:   $(id)"
echo "Connection threshold: ${CONN_THRESHOLD}"
echo "Nezha only mode: ${NEZHA_ONLY}"
echo

echo "Virtualization:"
systemd-detect-virt 2>/dev/null || true
echo

echo "Uptime:"
uptime 2>/dev/null || true
echo

if [ "$(id -u)" != "0" ]; then
  host_warn "Not running as root. Some checks may be incomplete."
else
  host_ok "Running as root."
fi

section "1. Host Top CPU / Memory"
echo "----- CPU TOP 30 -----"
ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --sort=-pcpu | head -30

echo
echo "----- MEM TOP 30 -----"
ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --sort=-pmem | head -30

section "2. Host Infection Indicators"

HOST_PROC_STRONG="$(ps auxww | awk '$1=="root"{print}' | grep -Eia "$STRONG_RE|$URL_EXEC_RE" | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_PROC_STRONG" ]; then
  echo "----- Host root suspicious processes -----"
  echo "$HOST_PROC_STRONG"
  host_high "Strong suspicious root process found on host."
else
  host_ok "No strong suspicious root process found on host."
fi

HOST_PROC_MAPPED="$(ps auxww | awk '$1!="root"{print}' | grep -Eia "$STRONG_RE|$URL_EXEC_RE" | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_PROC_MAPPED" ]; then
  echo
  echo "----- Non-root or container-mapped suspicious processes -----"
  echo "$HOST_PROC_MAPPED"
  host_warn "Suspicious mapped process found. Check container scan result."
fi

section "3. Host Nezha Related Items"
HOST_NEZHA="$(ps auxww | grep -Eia 'nezha-agent|/opt/nezha|/etc/nezha|nezha' | grep -vE 'grep|nezhajc' || true)"
if [ -n "$HOST_NEZHA" ]; then
  echo "----- Host Nezha related processes -----"
  echo "$HOST_NEZHA"
else
  echo "No host Nezha process found."
fi

echo
echo "----- Host Nezha related files -----"
find /etc/systemd/system /lib/systemd/system /opt /etc -maxdepth 4 \
  \( -iname '*nezha*' -o -iname 'config*.yml' \) -ls 2>/dev/null | head -200 || true

section "4. Host ld.so.preload"
if [ -e /etc/ld.so.preload ]; then
  PRELOAD_CONTENT="$(cat /etc/ld.so.preload 2>/dev/null || true)"
  ls -lah /etc/ld.so.preload 2>/dev/null
  lsattr /etc/ld.so.preload 2>/dev/null || true
  echo "----- Content -----"
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

    host_high "/etc/ld.so.preload exists and matches malicious indicators."
  else
    host_warn "/etc/ld.so.preload exists. Manual check required."
  fi
else
  host_ok "/etc/ld.so.preload does not exist."
fi

section "5. Host Strong Temp Files"
HOST_TMP_STRONG="$(find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null | grep -Eia 'SystemLog|/tmp/b$|download\.sh|ice\.sh|harvest\.sh|xmrig\.sh|xmrig|kinsing|kdevtmpfsi|usranalyse' || true)"

if [ -n "$HOST_TMP_STRONG" ]; then
  echo "$HOST_TMP_STRONG"
  host_high "Strong malicious temp file found on host."
else
  host_ok "No strong malicious temp file found on host."
fi

HOST_TMP_ALL="$(find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null || true)"
if [ -n "$HOST_TMP_ALL" ]; then
  echo
  echo "----- All executable files in host temp dirs. Manual check only. -----"
  echo "$HOST_TMP_ALL"
fi

section "6. Host cron / systemd / startup strong indicators"

HOST_CRON_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/cron* /var/spool/cron* 2>/dev/null || true)"
if [ -n "$HOST_CRON_STRONG" ]; then
  echo "----- Host cron strong indicators -----"
  echo "$HOST_CRON_STRONG"
  host_high "Strong suspicious cron item found on host."
else
  host_ok "No strong suspicious cron item found on host."
fi

HOST_SYSD_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/systemd/system /lib/systemd/system 2>/dev/null || true)"
if [ -n "$HOST_SYSD_STRONG" ]; then
  echo
  echo "----- Host systemd strong indicators -----"
  echo "$HOST_SYSD_STRONG"
  host_high "Strong suspicious systemd item found on host."
else
  host_ok "No strong suspicious systemd item found on host."
fi

HOST_START_STRONG="$(grep -RInE "$STRONG_RE|$URL_EXEC_RE" /etc/rc.local /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null || true)"
if [ -n "$HOST_START_STRONG" ]; then
  echo
  echo "----- Host startup strong indicators -----"
  echo "$HOST_START_STRONG"
  host_high "Strong suspicious startup item found on host."
else
  host_ok "No strong suspicious startup item found on host."
fi

section "7. Host Users and SSH"
echo "----- UID 0 users -----"
UID0="$(awk -F: '$3==0 {print}' /etc/passwd)"
echo "$UID0"

UID0_COUNT="$(echo "$UID0" | grep -c .)"
if [ "$UID0_COUNT" -gt 1 ]; then
  host_high "Multiple UID 0 users found."
else
  host_ok "UID 0 user count is normal."
fi

echo
echo "----- root authorized_keys -----"
if [ -f /root/.ssh/authorized_keys ]; then
  ls -lah /root/.ssh/authorized_keys
  cat /root/.ssh/authorized_keys
  host_warn "root authorized_keys exists. Manual check required."
else
  host_ok "root authorized_keys does not exist."
fi

section "8. Host Deleted Running Executables"
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
  host_warn "Deleted running executable found. Manual check required."
else
  host_ok "No deleted running executable found."
fi

section "9. Host Network"
echo "----- Listening ports -----"
ss -lntup 2>/dev/null || true

echo
echo "----- Suspicious host connections -----"
HOST_NET_SUSP="$(ss -tunp 2>/dev/null | grep -Eia 'xmrig|miner|SystemLog|/tmp|/dev/shm|/var/tmp|stratum|3333|4444|5555|7777|14444|usranalyse|86\.54\.82\.179|152\.42\.182\.35' || true)"
if [ -n "$HOST_NET_SUSP" ]; then
  echo "$HOST_NET_SUSP"
  host_warn "Suspicious host network connection found."
else
  host_ok "No common malicious host network connection found."
fi

section "10. Incus High-Risk Config"
if has_cmd incus; then
  echo "----- Incus containers -----"
  incus list 2>/dev/null || true

  echo
  echo "----- High-risk config filter -----"

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
      escape_risk "Instance $cname has privileged/raw/socket/host-mount config."
    fi
  done < <(incus list -c ns --format csv 2>/dev/null)

else
  host_warn "incus command not found. Skip Incus config check."
fi

if [ "$SCAN_CONTAINER" -eq 1 ]; then
  section "11. Container Scan. Nezha containers are prioritized."

  if ! has_cmd incus; then
    echo "incus command not found. Skip container scan."
  else
    while IFS=, read -r cname cstatus; do
      [ -z "$cname" ] && continue

      if [ "$cstatus" != "RUNNING" ]; then
        container_skipped "$cname" "$cstatus" "not running"
        continue
      fi

      C_HIGH=0
      C_WARN=0
      C_REASON=""
      C_NEZHA="NO"

      echo
      echo "================ Container: $cname [$cstatus] ================"

      echo "----- Nezha installation check -----"
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
        C_NEZHA="YES"
        CONTAINER_NEZHA_COUNT=$((CONTAINER_NEZHA_COUNT + 1))
        NEZHA_LIST="${NEZHA_LIST}
[NEZHA] ${cname}"
        echo "[NEZHA-FOUND] $cname"
      else
        echo "[NEZHA-NOT-FOUND] $cname"
      fi

      if [ "$NEZHA_ONLY" -eq 1 ] && [ "$C_NEZHA" != "YES" ]; then
        container_skipped "$cname" "$cstatus" "no nezha, skipped by --nezha-only"
        continue
      fi

      echo
      echo "----- Nezha directory suspicious file check -----"
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
        C_REASON="${C_REASON} nezha_dir_suspicious"
      else
        echo "Not found."
      fi

      echo
      echo "----- Process strong indicator check -----"
      C_PS="$(run_in_container "$cname" \
        'ps auxww 2>/dev/null | grep -Eia "xmrig|miner|kinsing|kdevtmpfsi|SystemLog|/tmp/b|/tmp/SystemLog|/tmp/download.sh|download.sh|ice.sh|harvest.sh|xmrig.sh|stratum|masscan|zmap|pnscan|/dev/shm|/var/tmp|usranalyse|ld.so.preload|recvp.php|curl .*sh|wget .*sh|curl.*\|.*sh|wget.*\|.*sh|86\.54\.82\.179|152\.42\.182\.35|mkdir -p /root/.ssh|chmod 700 /root/.ssh|\{\}" | grep -v grep' || true)"

      if [ -n "$C_PS" ]; then
        echo "$C_PS"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_process"
      else
        echo "Not found."
      fi

      echo
      echo "----- Public remote IP / connection count. Threshold: ${CONN_THRESHOLD} -----"
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
        C_REASON="${C_REASON} network_tool_missing"
      else
        TOTAL_PUBLIC_CONN="$(echo "$C_CONN" | awk -F= '/TOTAL_PUBLIC_CONN=/{print $2}' | tail -1)"
        UNIQUE_PUBLIC_IP="$(echo "$C_CONN" | awk -F= '/UNIQUE_PUBLIC_IP=/{print $2}' | tail -1)"

        TOTAL_PUBLIC_CONN="${TOTAL_PUBLIC_CONN:-0}"
        UNIQUE_PUBLIC_IP="${UNIQUE_PUBLIC_IP:-0}"

        if [ "$UNIQUE_PUBLIC_IP" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
          C_HIGH=1
          C_REASON="${C_REASON} massive_unique_ip_${UNIQUE_PUBLIC_IP}"
        elif [ "$TOTAL_PUBLIC_CONN" -ge "$CONN_THRESHOLD" ] 2>/dev/null; then
          C_HIGH=1
          C_REASON="${C_REASON} massive_public_conn_${TOTAL_PUBLIC_CONN}"
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
          C_REASON="${C_REASON} ld.so.preload"
        else
          C_WARN=1
          C_REASON="${C_REASON} preload_exists"
        fi
      else
        echo "Not found."
      fi

      echo
      echo "----- Executable files in temp dirs -----"
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
        echo "Not found."
      fi

      echo
      echo "----- cron suspicious items -----"
      C_CRON="$(run_in_container "$cname" \
        '{
          crontab -l 2>/dev/null
          grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/cron* /etc/crontabs /etc/periodic /var/spool/cron* 2>/dev/null
        } | head -200' || true)"

      if [ -n "$C_CRON" ]; then
        echo "$C_CRON"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_cron"
      else
        echo "Not found."
      fi

      echo
      echo "----- startup suspicious items -----"
      C_STARTUP="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|ld.so.preload|usranalyse|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|/root/.ssh|86\.54\.82\.179|152\.42\.182\.35" /etc/systemd/system /lib/systemd/system /etc/init.d /etc/runlevels /etc/profile /etc/profile.d /root/.bashrc /root/.profile 2>/dev/null | head -200' || true)"

      if [ -n "$C_STARTUP" ]; then
        echo "$C_STARTUP"
        C_HIGH=1
        C_REASON="${C_REASON} suspicious_startup"
      else
        echo "Not found."
      fi

      echo
      echo "----- SSH authorized_keys. Warning only. -----"
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
        echo "Not found."
      fi

      echo
      echo "----- shell history suspicious items. Warning only. -----"
      C_HISTORY="$(run_in_container "$cname" \
        'grep -RInE "curl|wget|base64|/tmp|/dev/shm|SystemLog|xmrig|miner|stratum|download.sh|ice.sh|harvest.sh|xmrig.sh|recvp.php|86\.54\.82\.179|152\.42\.182\.35" /root/.bash_history /home/*/.bash_history 2>/dev/null | head -120' || true)"

      if [ -n "$C_HISTORY" ]; then
        echo "$C_HISTORY"
        C_WARN=1
        C_REASON="${C_REASON} suspicious_history"
      else
        echo "Not found."
      fi

      if [ "$C_HIGH" -eq 1 ]; then
        container_infected "$cname" "$C_REASON" "$C_NEZHA"
      elif [ "$C_WARN" -eq 1 ]; then
        container_warn "$cname" "$C_REASON" "$C_NEZHA"
      else
        echo "[CONTAINER-OK] $cname | NEZHA:${C_NEZHA} | No obvious infection signs."
      fi

    done < <(incus list -c ns --format csv 2>/dev/null)
  fi
else
  section "11. Container Scan"
  echo "--host-only used. Skip container scan."
fi

section "12. Final Result"
echo "Report: $REPORT"
echo

if [ "$HOST_HIGH" -eq 1 ]; then
  echo "Host infection status: HIGH / SUSPICIOUS"
elif [ "$HOST_WARN" -eq 1 ]; then
  echo "Host infection status: WARNING / MANUAL CHECK REQUIRED"
else
  echo "Host infection status: NO OBVIOUS SIGNS"
fi

if [ "$ESCAPE_RISK" -eq 1 ]; then
  echo "Container escape risk config: FOUND"
else
  echo "Container escape risk config: NOT FOUND"
fi

echo
echo "Nezha containers count: $CONTAINER_NEZHA_COUNT"
if [ "$CONTAINER_NEZHA_COUNT" -gt 0 ]; then
  echo "$NEZHA_LIST"
else
  echo "No Nezha container found."
fi

echo
echo "Infected Nezha containers count: $CONTAINER_NEZHA_INFECTED_COUNT"
if [ "$CONTAINER_NEZHA_INFECTED_COUNT" -gt 0 ]; then
  echo "$NEZHA_INFECTED_LIST"
else
  echo "No infected Nezha container found."
fi

echo
echo "All infected containers count: $CONTAINER_INFECTED_COUNT"
if [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  echo "$INFECTED_LIST"
else
  echo "No infected container found."
fi

echo
echo "Warning containers count: $CONTAINER_WARN_COUNT"
if [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  echo "$WARN_LIST"
else
  echo "No warning-only container found."
fi

echo
echo "Skipped containers count: $CONTAINER_SKIPPED_COUNT"
if [ "$CONTAINER_SKIPPED_COUNT" -gt 0 ]; then
  echo "$SKIPPED_LIST"
fi

echo
echo "Rules:"
echo "1. Host is not marked infected just because UID 1000000 container-mapped process is suspicious."
echo "2. Host is marked HIGH only when root process, malicious ld.so.preload, strong temp file, cron, or systemd indicator is found."
echo "3. Containers with Nezha are listed as [NEZHA] and checked more carefully."
echo "4. Container is marked INFECTED if public remote IP count or public connection count >= ${CONN_THRESHOLD}."
echo "5. Container is marked INFECTED if /tmp/SystemLog, /tmp/b, download.sh, ice.sh, harvest.sh, xmrig.sh, ld.so.preload, suspicious cron, or download-exec command is found."
echo "6. authorized_keys and shell history are warning-only."
echo "7. Use --nezha-only to scan only containers with Nezha."
echo "8. No script can prove a system is 100 percent clean."

if [ "$HOST_HIGH" -eq 1 ] || [ "$ESCAPE_RISK" -eq 1 ] || [ "$CONTAINER_INFECTED_COUNT" -gt 0 ]; then
  exit 2
elif [ "$HOST_WARN" -eq 1 ] || [ "$CONTAINER_WARN_COUNT" -gt 0 ]; then
  exit 1
else
  exit 0
fi
