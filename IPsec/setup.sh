#! /bin/bash
HOST_IP=$(ip addr | grep "global eth0" | awk -F "/" '{ print $1}' | awk '{print $2}')
echo "client email:"
read email
pacman -S strongswan

cd /etc/ipsec.d/
ipsec pki --gen --type rsa --size 4096 --outform pem > private/strongswanKey.pem
chmod 600 private/strongswanKey.pem

ipsec pki --self --ca --lifetime 3650 --in private/strongswanKey.pem --type rsa --dn "C=CH, O=strongSwan, CN=strongSwan Root CA" \
	   --outform pem > cacerts/strongswanCert.pem

ipsec pki --gen --type rsa --size 2048 --outform pem > private/vpnHostKey.pem
chmod 600 private/vpnHostKey.pem

ipsec pki --pub --in private/vpnHostKey.pem --type rsa | \
	 ipsec pki --issue --lifetime 730 \
	  --cacert cacerts/strongswanCert.pem \
	  --cakey private/strongswanKey.pem \
	  --dn "C=CH, O=strongSwan, CN=$HOST_IP" \
	  --san vpn.example.com \
	  --flag serverAuth --flag ikeIntermediate \
	  --outform pem > certs/vpnHostCert.pem

ipsec pki --gen --type rsa --size 2048 --outform pem > private/ClientKey.pem
chmod 600 private/ClientKey.pem

ipsec pki --pub --in private/ClientKey.pem --type rsa | \
	 ipsec pki --issue --lifetime 730 \
	  --cacert cacerts/strongswanCert.pem \
	  --cakey private/strongswanKey.pem \
	  --dn "C=CH, O=strongSwan, CN=$email" \
	  --san myself@example.com \
	  --outform pem > certs/ClientCert.pem

openssl pkcs12 -export -inkey private/ClientKey.pem \
	  -in certs/ClientCert.pem -name "My own VPN client certificate" \
	  -certfile cacerts/strongswanCert.pem \
	  -caname "strongSwan Root CA" \
	  -out Client.p12
