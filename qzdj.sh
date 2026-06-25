#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请以 root 身份运行此脚本。${NC}"
  exit 1
fi

# Constants
CONF_DIR="/etc/sing-box"
CONF_FILE="$CONF_DIR/config.json"
BIN_FILE="/usr/local/bin/sing-box"
KEEP_ALIVE_FILE="/root/keep_alive.sh"

function print_menu() {
    clear
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${GREEN}       Sing-Box 全局透明出口代理部署脚本 (增强版)${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo
    echo -e " ${YELLOW}1.${NC} 🚀 一键部署 / 重新配置 (支持 SOCKS5/SS/VLESS)"
    echo -e " ${YELLOW}2.${NC} 🔄 重新安装 Sing-box 核心 (1.12.15)"
    echo -e " ${YELLOW}3.${NC} 📊 查看运行状态与连接日志"
    echo -e " ${YELLOW}4.${NC} 🛑 停止服务并卸载清理"
    echo -e " ${YELLOW}0.${NC} 退出脚本"
    echo
    echo -e "${BLUE}======================================================${NC}"
}

function check_status() {
    clear
    echo -e "${BLUE}=== Sing-box 运行状态 ===${NC}"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "Sing-box 服务: ${GREEN}运行中 (Active)${NC}"
    else
        echo -e "Sing-box 服务: ${RED}未运行 (Inactive)${NC}"
    fi

    if systemctl is-active --quiet keep-alive; then
        echo -e "路由保活 服务: ${GREEN}运行中 (Active)${NC}"
    else
        echo -e "路由保活 服务: ${RED}未运行 (Inactive)${NC}"
    fi

    if [ -f "$BIN_FILE" ]; then
        VER=$($BIN_FILE version | head -1)
        echo -e "当前安装核心: ${YELLOW}$VER${NC}"
    else
        echo -e "当前安装核心: ${RED}未安装${NC}"
    fi

    echo
    echo -e "正在测试外部连接 (检测当前公网IP)..."
    IP=$(curl -s --connect-timeout 5 https://api.ipify.org)
    if [ -n "$IP" ]; then
        echo -e "当前出口 IP: ${GREEN}$IP${NC}"
    else
        echo -e "出口 IP 检测失败，网络可能异常。${NC}"
    fi
    echo
    echo "最新日志 (sing-box):"
    journalctl -u sing-box -n 10 --no-pager
    echo
    read -p "按回车键返回主菜单..."
}

function uninstall() {
    echo -e "${RED}正在卸载 Sing-box 及配置...${NC}"
    systemctl stop sing-box keep-alive 2>/dev/null
    systemctl disable sing-box keep-alive 2>/dev/null
    
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/keep-alive.service
    systemctl daemon-reload
    
    rm -rf "$CONF_DIR"
    rm -f "$BIN_FILE"
    rm -f "$KEEP_ALIVE_FILE"
    
    # 清理可能残留的 ip rule / route
    ip link set dev tun0 down 2>/dev/null
    ip route flush table 100 2>/dev/null
    ip rule del lookup 100 2>/dev/null
    
    rm -f "$0"
    echo -e "${GREEN}卸载完成！脚本本身已删除。建议重启一次服务器以彻底清理系统路由表。${NC}"
    exit 0
}

function install_singbox() {
    LATEST_VERSION="1.12.15"
    echo -e "目标版本: ${GREEN}${LATEST_VERSION}${NC}"
    
    ARCH="amd64"
    if [ "$(uname -m)" == "aarch64" ]; then
        ARCH="arm64"
    fi

    FILE_NAME="sing-box-${LATEST_VERSION}-linux-${ARCH}"
    TAR_NAME="${FILE_NAME}.tar.gz"
    URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/${TAR_NAME}"
    PROXY_URL="https://mirror.ghproxy.com/${URL}"

    echo "开始下载: $URL"
    curl -L -O "$URL"
    if [ ! -s "$TAR_NAME" ]; then
        echo -e "${YELLOW}直接下载失败，尝试使用代理镜像下载...${NC}"
        curl -L -O "$PROXY_URL"
    fi

    if [ ! -s "$TAR_NAME" ]; then
        echo -e "${RED}下载失败，请检查网络连接！${NC}"
        exit 1
    fi

    tar -xzf "$TAR_NAME"
    mv "${FILE_NAME}/sing-box" "$BIN_FILE"
    chmod +x "$BIN_FILE"
    rm -rf "$FILE_NAME" "$TAR_NAME"

    echo -e "${GREEN}Sing-box v${LATEST_VERSION} 安装/更新成功！${NC}"
}

function generate_outbound() {
    if [ "$PROTOCOL" == "socks" ]; then
        OUTBOUND_JSON=$(cat <<EOF
    {
      "type": "socks",
      "tag": "proxy",
      "server": "$PROXY_ADDR",
      "server_port": $PROXY_PORT,
      "version": "5",
      "username": "$PROXY_USER",
      "password": "$PROXY_PASS",
      "udp_over_tcp": true,
      "routing_mark": 666
    }
EOF
)
    elif [ "$PROTOCOL" == "vless" ]; then
        OUTBOUND_JSON=$(cat <<EOF
    {
      "type": "vless",
      "tag": "proxy",
      "server": "$PROXY_ADDR",
      "server_port": $PROXY_PORT,
      "uuid": "$PROXY_UUID",
      "network": "tcp",
      "tls": { "enabled": false },
      "packet_encoding": "xudp",
      "routing_mark": 666
    }
EOF
)
    elif [ "$PROTOCOL" == "shadowsocks" ]; then
        OUTBOUND_JSON=$(cat <<EOF
    {
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "$PROXY_ADDR",
      "server_port": $PROXY_PORT,
      "method": "$SS_METHOD",
      "password": "$PROXY_PASS",
      "udp_over_tcp": true,
      "routing_mark": 666
    }
EOF
)
    fi
}

function interactive_config() {
    clear
    echo -e "${BLUE}=== 1. 物理网卡选择 ===${NC}"
    echo "正在检测网卡接口..."
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE "^lo|^tun|^docker|^veth")
    declare -a iface_list
    i=1
    for iface in $interfaces; do
        iface_list[$i]=$iface
        i=$((i+1))
    done

    if [ ${#iface_list[@]} -eq 0 ]; then
        echo -e "${RED}未检测到有效物理网卡，请检查网络配置。${NC}"
        exit 1
    fi

    for index in "${!iface_list[@]}"; do
        echo " [$index] ${iface_list[$index]}"
    done
    read -p "请输入要代理的网卡序号 (默认: 1): " selection
    selection=${selection:-1}
    WAN_IFACE="${iface_list[$selection]}"
    echo -e "已选择出网网卡: ${GREEN}$WAN_IFACE${NC}"
    echo

    echo -e "${BLUE}=== 2. 代理协议选择 ===${NC}"
    echo " 1. SOCKS5"
    echo " 2. Shadowsocks"
    echo " 3. VLESS (TCP明文)"
    read -p "请输入序号 (1-3): " PROTO_CHOICE

    case "$PROTO_CHOICE" in
        1)
            PROTOCOL="socks"
            echo -e "${YELLOW}[SOCKS5]${NC} 请输入节点信息:"
            read -p "地址 (IP/域名): " PROXY_ADDR
            read -p "端口: " PROXY_PORT
            read -p "用户名 (可选): " PROXY_USER
            read -p "密码 (可选): " PROXY_PASS
            ;;
        2)
            PROTOCOL="shadowsocks"
            echo -e "${YELLOW}[Shadowsocks]${NC} 请输入节点信息:"
            read -p "地址 (IP/域名): " PROXY_ADDR
            read -p "端口: " PROXY_PORT
            read -p "密码: " PROXY_PASS
            echo "常用加密方式: 1.aes-256-gcm 2.aes-128-gcm 3.chacha20-poly1305"
            read -p "请输入加密方式名称 (默认 aes-256-gcm): " SS_METHOD
            SS_METHOD=${SS_METHOD:-aes-256-gcm}
            ;;
        3)
            PROTOCOL="vless"
            echo -e "${YELLOW}[VLESS]${NC} 请输入节点信息:"
            read -p "地址 (IP/域名): " PROXY_ADDR
            read -p "端口: " PROXY_PORT
            read -p "UUID: " PROXY_UUID
            ;;
        *)
            echo -e "${RED}选择无效！${NC}"
            exit 1
            ;;
    esac

    if [[ -z "$PROXY_ADDR" ]] || [[ -z "$PROXY_PORT" ]]; then
        echo -e "${RED}地址和端口不能为空！${NC}"
        exit 1
    fi

    echo
    echo -e "${BLUE}=== 3. 路由与分流规则 ===${NC}"
    echo " 1. 推荐分流 (国内常见源、GitHub、Docker直连，其他走代理)"
    echo " 2. 全局代理 (所有流量100%走代理，除了内网IP)"
    read -p "请选择分流模式 (1-2，默认: 1): " SPLIT_CHOICE
    SPLIT_CHOICE=${SPLIT_CHOICE:-1}

    if [ "$SPLIT_CHOICE" == "1" ]; then
        ENABLE_SPLIT="true"
    else
        ENABLE_SPLIT="false"
    fi
}

function deploy() {
    interactive_config

    if [ ! -f "$BIN_FILE" ]; then
        install_singbox
    fi

    generate_outbound

    mkdir -p "$CONF_DIR"

    PROXY_IP=$(getent hosts "$PROXY_ADDR" | awk '{print $1}' | head -1)
    PROXY_IP=${PROXY_IP:-$PROXY_ADDR}

    if [ "$ENABLE_SPLIT" == "true" ]; then
        SPLIT_RULES=$(cat <<EOF
      { "domain_suffix": ["github.com", "githubusercontent.com", "githubassets.com", "github.io"], "outbound": "direct" },
      { "domain_suffix": ["docker.io", "docker.com", "dockerhub.com"], "outbound": "direct" },
      { "domain_suffix": ["debian.org", "ubuntu.com", "canonical.com"], "outbound": "direct" },
      { "domain_suffix": ["centos.org", "fedoraproject.org", "redhat.com"], "outbound": "direct" },
      { "domain_suffix": ["alpinelinux.org", "archlinux.org"], "outbound": "direct" },
      { "domain_suffix": ["npmjs.org", "npmjs.com", "yarnpkg.com"], "outbound": "direct" },
      { "domain_suffix": ["pypi.org", "pythonhosted.org"], "outbound": "direct" },
      { "domain_suffix": ["golang.org", "go.dev", "proxy.golang.org"], "outbound": "direct" },
      { "domain_suffix": ["maven.org", "mvnrepository.com"], "outbound": "direct" },
      { "domain_suffix": ["rubygems.org", "crates.io", "packagist.org"], "outbound": "direct" },
      { "domain_suffix": ["cloudflare.com", "fastly.net", "akamai.net"], "outbound": "direct" },
EOF
)
    else
        SPLIT_RULES=""
    fi

    cat > "$CONF_FILE" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      { "tag": "dns_direct", "address": "223.5.5.5", "detour": "direct" },
      { "tag": "dns_proxy", "address": "8.8.8.8", "detour": "proxy" }
    ],
    "rules": [
      { "domain": ["$PROXY_ADDR"], "server": "dns_direct" }
    ],
    "final": "dns_proxy"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["10.255.0.1/30"],
      "mtu": 1520,
      "stack": "gvisor",
      "auto_route": false,
      "strict_route": false,
      "sniff": true,
      "sniff_override_destination": false,
      "endpoint_independent_nat": true
    }
  ],
  "outbounds": [
    $OUTBOUND_JSON,
    { 
      "type": "direct", 
      "tag": "direct", 
      "bind_interface": "$WAN_IFACE" 
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_cidr": ["$PROXY_IP/32"], "outbound": "direct" },
      { "domain": ["$PROXY_ADDR"], "outbound": "direct" },
$SPLIT_RULES
      { "ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"], "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
EOF

    # Create keep alive
    SSH_CLIENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')
    if [ -z "$SSH_CLIENT_IP" ]; then
        SSH_CLIENT_IP=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
    fi

    cat > "$KEEP_ALIVE_FILE" << EOF
#!/bin/bash
IFACE_WAN="$WAN_IFACE"
IFACE_TUN="tun0"
MARK_OUTBOUND_HEX="0x29a"
MARK_INBOUND_HEX="0x114"
TABLE_TUN="100"
SSH_CLIENT_IP="$SSH_CLIENT_IP"

sysctl -w net.ipv4.ip_forward=1 > /dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 > /dev/null
sysctl -w net.ipv4.conf.\$IFACE_WAN.rp_filter=2 > /dev/null

echo "等待 tun0 接口创建..."
for i in {1..30}; do
    if ip link show \$IFACE_TUN &>/dev/null; then
        echo "tun0 接口已创建"
        break
    fi
    sleep 1
done

while true; do
    RULE_EXIST=\$(ip rule show | grep "lookup \$TABLE_TUN")
    ROUTE_EXIST=\$(ip route show table \$TABLE_TUN | grep "default")
    if [[ -z "\$RULE_EXIST" ]] || [[ -z "\$ROUTE_EXIST" ]]; then
        ip link set dev \$IFACE_TUN up 2>/dev/null
        ip route flush table \$TABLE_TUN
        ip route add default dev \$IFACE_TUN table \$TABLE_TUN 2>/dev/null
        
        if [ -n "\$SSH_CLIENT_IP" ]; then
            ip rule add from \$SSH_CLIENT_IP lookup main priority 10 2>/dev/null
            ip rule add to \$SSH_CLIENT_IP lookup main priority 10 2>/dev/null
        fi
        ip rule add ipproto tcp sport 22 lookup main priority 15 2>/dev/null
        ip rule add ipproto tcp dport 22 lookup main priority 15 2>/dev/null
        
        ip rule add fwmark \$MARK_INBOUND_HEX lookup main priority 50 2>/dev/null
        ip rule add fwmark \$MARK_OUTBOUND_HEX lookup main priority 60 2>/dev/null
        ip rule add to 10.0.0.0/8 lookup main priority 70 2>/dev/null
        ip rule add to 172.16.0.0/12 lookup main priority 70 2>/dev/null
        ip rule add to 192.168.0.0/16 lookup main priority 70 2>/dev/null
        
        # GitHub & Docker IPs
        ip rule add to 140.82.112.0/20 lookup main priority 70 2>/dev/null
        ip rule add to 143.55.64.0/20 lookup main priority 70 2>/dev/null
        ip rule add to 185.199.108.0/22 lookup main priority 70 2>/dev/null
        ip rule add to 192.30.252.0/22 lookup main priority 70 2>/dev/null
        ip rule add to 44.205.64.0/20 lookup main priority 70 2>/dev/null
        ip rule add to 52.1.184.0/21 lookup main priority 70 2>/dev/null
        
        ip rule add from all lookup \$TABLE_TUN priority 100 2>/dev/null
    fi
    if ! iptables -t mangle -C PREROUTING -i \$IFACE_WAN -m conntrack --ctstate NEW -j CONNMARK --set-mark \$MARK_INBOUND_HEX 2>/dev/null; then
         iptables -t mangle -A PREROUTING -i \$IFACE_WAN -p tcp --dport 22 -j ACCEPT 2>/dev/null
         iptables -t mangle -A PREROUTING -d 140.82.112.0/20 -j ACCEPT 2>/dev/null
         iptables -t mangle -A PREROUTING -d 185.199.108.0/22 -j ACCEPT 2>/dev/null
         iptables -t mangle -A PREROUTING -d 44.205.64.0/20 -j ACCEPT 2>/dev/null
         
         iptables -t mangle -A PREROUTING -i \$IFACE_WAN -m conntrack --ctstate NEW -j CONNMARK --set-mark \$MARK_INBOUND_HEX
         iptables -t mangle -A PREROUTING -m connmark --mark \$MARK_INBOUND_HEX -j CONNMARK --restore-mark
         iptables -t mangle -A OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null
         
         iptables -t mangle -A OUTPUT -d 140.82.112.0/20 -j ACCEPT 2>/dev/null
         iptables -t mangle -A OUTPUT -d 185.199.108.0/22 -j ACCEPT 2>/dev/null
         iptables -t mangle -A OUTPUT -d 44.205.64.0/20 -j ACCEPT 2>/dev/null
         
         iptables -t mangle -A OUTPUT -m connmark --mark \$MARK_INBOUND_HEX -j CONNMARK --restore-mark
    fi
    sleep 2
done
EOF
    chmod +x "$KEEP_ALIVE_FILE"

    # Create Systemd Services
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target network-online.target
[Service]
Type=simple
Environment="ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true"
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=3
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/keep-alive.service << 'EOF'
[Unit]
Description=Sing-box Routing Keep Alive Daemon
After=network.target sing-box.service
Requires=sing-box.service
[Service]
Type=simple
ExecStartPre=/bin/sleep 3
ExecStart=/bin/bash /root/keep_alive.sh
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sing-box keep-alive 2>/dev/null
    systemctl restart sing-box keep-alive

    echo -e "${GREEN}部署完成！Sing-box 已启动并接管流量。${NC}"
    echo -e "你可以前往主菜单选择【3】查看状态并验证出口IP。"
    read -p "按回车键返回主菜单..."
}

while true; do
    print_menu
    read -p "请输入选项: " CHOICE
    case "$CHOICE" in
        1) deploy ;;
        2) install_singbox; read -p "按回车键返回主菜单..." ;;
        3) check_status ;;
        4) uninstall ;;
        0) echo -e "${GREEN}感谢使用，再见！${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选项，请重新输入。${NC}"; sleep 1 ;;
    esac
done
