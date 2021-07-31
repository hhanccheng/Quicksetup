#! /bin/bash

YOUR_IPSEC_PSK='test'
YOUR_USERNAME='test'
YOUR_PASSWORD='test'

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr()  { echo "Error: $1" >&2; exit 1; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

pacman -S strongswan xl2tpd

[ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
[ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
[ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"

if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  echo "VPN credentials not set by user. Generating random PSK and password..."
  VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 20)
  VPN_USER=vpnuser
  VPN_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)
fi

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit the script and re-enter them."
fi

if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
  || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; } then
  exiterr "The DNS server specified is invalid."
fi

if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
  exiterr "IPTables check failed. Reboot and re-run this script."
fi


echo "Trying to auto discover IP of this server..."

# In case auto IP discovery fails, enter server's public IP here.
public_ip=${VPN_PUBLIC_IP:-''}
check_ip "$public_ip" || public_ip=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
check_ip "$public_ip" || exiterr "Cannot detect this server's public IP. Edit the script and manually enter it."

echo "Installing packages required for the VPN..."

pacman -S ppp xl2tpd fail2ban

echo "Creating VPN configuration..."

L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.42.1'}
L2TP_POOL=${VPN_L2TP_POOL:-'192.168.42.10-192.168.42.250'}
XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}
DNS_SRVS="\"$DNS_SRV1 $DNS_SRV2\""
[ -n "$VPN_DNS_SRV1" ] && [ -z "$VPN_DNS_SRV2" ] && DNS_SRVS="$DNS_SRV1"

# Create IPsec config
cat >> /etc/ipsec.conf <<EOF
config setup

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    keyexchange=ikev1
    authby=secret
    ike=aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes128-sha1-modp1024,3des-sha1-modp1024!

conn L2TP-PSK
    keyexchange=ikev1
    left=%defaultroute
    auto=add
    authby=secret
    type=transport
    leftprotoport=17/1701
    rightprotoport=17/1701
    right=192.3.48.74
EOF

if uname -m | grep -qi '^arm'; then
  if ! modprobe -q sha512; then
    sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
  fi
fi

# Specify IPsec PSK
conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$YOUR_IPSEC_PSK"
EOF

# Create xl2tpd config
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes

[lac vpn-connection]
lns = 192.3.48.74
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
EOF

# Set xl2tpd options
cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-mschap-v2
noccp
noauth
idle 1800
mtu 1410
mru 1410
defaultroute
usepeerdns
debug
connect-delay 5000
name $YOUR_USERNAME
password $YOUR_PASSWORD
EOF

if [ -z "$VPN_DNS_SRV1" ] || [ -n "$VPN_DNS_SRV2" ]; then
cat >> /etc/ppp/options.xl2tpd <<EOF
ms-dns $DNS_SRV2
EOF
fi

# Create VPN credentials
conf_bk "/etc/ppp/chap-secrets"
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF

conf_bk "/etc/ipsec.d/passwd"
VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF

echo "Updating sysctl settings..."
cat >> /etc/sysctl.conf <<EOF

kernel.msgmnb = 65536
kernel.msgmax = 65536

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0

net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF

echo "Updating iptables rules..."

IPT_FILE=/etc/iptables.rules
IPT_FILE2=/etc/iptables/rules.v4

NET_IFACE=eth0

ipi='iptables -I INPUT'
ipf='iptables -I FORWARD'
ipp='iptables -t nat -I POSTROUTING'
res='RELATED,ESTABLISHED'
systemctl stop fail2ban
iptables-save > "$IPT_FILE.old-$SYS_DT"
$ipi 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
$ipi 2 -m conntrack --ctstate INVALID -j DROP
$ipi 3 -m conntrack --ctstate "$res" -j ACCEPT
$ipi 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
$ipi 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
$ipi 6 -p udp --dport 1701 -j DROP
$ipf 1 -m conntrack --ctstate INVALID -j DROP
$ipf 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate "$res" -j ACCEPT
$ipf 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
$ipf 4 -i ppp+ -o ppp+ -j ACCEPT
$ipf 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate "$res" -j ACCEPT
$ipf 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
$ipf 7 -s "$XAUTH_NET" -o ppp+ -j ACCEPT
iptables -A FORWARD -j DROP
$ipp -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE
$ipp -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
iptables-save >> "$IPT_FILE"

if [ -f "$IPT_FILE2" ]; then
  conf_bk "$IPT_FILE2"
  /bin/cp -f "$IPT_FILE" "$IPT_FILE2"
fi

echo "Enabling services on boot..."

IPT_PST=/etc/init.d/iptables-persistent
IPT_PST2=/usr/share/netfilter-persistent/plugins.d/15-ip4tables
ipt_load=1
if [ -f "$IPT_FILE2" ] && { [ -f "$IPT_PST" ] || [ -f "$IPT_PST2" ]; }; then
  ipt_load=0
fi

if [ "$ipt_load" = "1" ]; then
  mkdir -p /etc/network/if-pre-up.d
cat > /etc/network/if-pre-up.d/iptablesload <<'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
  chmod +x /etc/network/if-pre-up.d/iptablesload

  if [ -f /usr/sbin/netplan ]; then
    mkdir -p /etc/systemd/system
cat > /etc/systemd/system/load-iptables-rules.service <<'EOF'
[Unit]
Description = Load /etc/iptables.rules
DefaultDependencies=no

Before=network-pre.target
Wants=network-pre.target

Wants=systemd-modules-load.service local-fs.target
After=systemd-modules-load.service local-fs.target

[Service]
Type=oneshot
ExecStart=/etc/network/if-pre-up.d/iptablesload

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable load-iptables-rules 2>/dev/null
  fi
fi

for svc in fail2ban ipsec xl2tpd strongswan; do
  update-rc.d "$svc" enable >/dev/null 2>&1
  systemctl enable "$svc" 2>/dev/null
done


echo "Starting services..."

chmod +x /etc/rc.local
chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*

mkdir -p /run/pluto
mkdir -p /var/run/xl2tpd
systemctl restart fail2ban
ipsec rereadsecrets
systemctl restart xl2tpd 
systemctl restart strongswan
sleep 8
ipsec up L2TP-PSK
sleep 8
bash -c 'echo "c vpn-connection" > /var/run/xl2tpd/l2tp-control'
sleep 8
ip address

cat <<EOF

================================================

Server IP: $public_ip
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD

================================================

EOF