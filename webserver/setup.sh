#! /bin/bash
#Get input of information
echo "Enter the Domain (example.com)"
read domain
echo "Enter the Email"
read email
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

systemctl start nginx
# wordpress & phpmyadmin
pacman -S wordpress phpmyadmin

#Importing configuration files
mv qhttpd.conf /etc/httpd/conf/httpd.conf
mv qnginx.conf /etc/nginx/nginx.conf
mv httpd-wordpress.conf /etc/httpd/conf/extra/
mv phpmyadmin.conf /etc/httpd/conf/extra/
mysql -uroot -p < wordpress.sql

# SSL
pacman -S certbot
certbot certonly --webroot --email $email -d www.$domain -d $domain -w /usr/share/nginx/html
sed -i "s/example.com/$domain/g" /etc/nginx/nginx.conf
systemctl enable httpd mariadb nginx
# Default: nginx index files in /ust/share/nginx/html with port 80, apache index file is in /srv/http with port 8080