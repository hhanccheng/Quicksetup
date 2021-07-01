# !/bin/bash

# Load the BBR kernel module.
echo "tcp_bbr" > /etc/modules-load.d/modules.conf
# Set the default congestion algorithm to BBR.
echo "net.core.default_qdisc=cake" > /etc/sysctl.d/bbr.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/bbr.conf
# edit the sshd_config & bashrc
mv parrot.bashrc /etc/bash.bashrc
mv sshd_config.conf /etc/ssh/sshd_config
# restart the sshd.service
systemctl restart sshd
