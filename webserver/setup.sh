#! /bin/bash

#Quick configuration of nginx front-end and apache back-end on archlinux
#apache
pacman -Syu apache
systemctl start httpd
#Database
pacman -S mariadb
mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
systemctl start mariadb
mysql_secure_installation
#php   
pacman -S php php-apache

#nginx
pacman -S nginx

#configuration files
mv qhttpd.conf /etc/httpd/conf/httpd.conf
mv qnginx.conf /etc/nginx/nginx.conf

systemctl enable httpd mariadb nginx
systemctl start httpd mariadb nginx

# Default: nginx index files in /ust/share/nginx/html with port 80, apache index file is in /srv/http with port 8080