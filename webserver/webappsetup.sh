# wordpress & phpmyadmin
pacman -S wordpress phpmyadmin

#confile cp
cp httpd-wordpress.conf /etc/httpd/conf/extra/
cp phpmyadmin.conf /etc/httpd/conf/extra/
cp qphp.ini /etc/php/php.ini
cp qwp-config.php /usr/share/webapps/wordpress/wp-conifg.php

mysql -uroot -p < wordpress.sql