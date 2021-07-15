#! /bin/bash
#Get input of information
echo "Enter the Domain (example.com)"
read domain
echo "Enter the Email"
read email
# SSL
pacman -Sy certbot
certbot certonly --webroot --email $email -d www.$domain -d $domain -w /usr/share/nginx/html
mv sslnginx.conf /etc/nginx/nginx.conf
sed -i "s/example.com/$domain/g" /etc/nginx/nginx.conf
systemctl restart httpd mariadb nginx

# auto renew