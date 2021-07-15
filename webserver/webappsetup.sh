# wordpress & phpmyadmin
pacman -S wordpress phpmyadmin

#confile cp
cp httpd-wordpress.conf /etc/httpd/conf/extra/
cp phpmyadmin.conf /etc/httpd/conf/extra/
cp php.ini /etc/php/php.ini
cp wp-config.php /usr/share/webapps/wordpress/wp-conifg.php

mysql -uroot -p < wordpress.sql

systemctl restart mariadb httpd nginx