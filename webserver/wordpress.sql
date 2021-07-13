CREATE DATABASE wordpress;
CREATE USER wpadmin@localhost;
SET PASSWORD FOR wpadmin@localhost= PASSWORD("wpasswd123");
GRANT ALL PRIVILEGES ON wordpress.* TO wpadmin@localhost IDENTIFIED BY 'wpasswd123';
FLUSH PRIVILEGES;
