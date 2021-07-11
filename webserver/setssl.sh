#! /bin/bash
#Get input of information
echo "Enter the Domain (example.com)"
read domain
echo "Enter the Email"
read email
# SSL
pacman -S certbot
certbot certonly --webroot --email $email -d www.$domain -d $domain -w /usr/share/nginx/html
sed -i "s/example.com/$domain/g" /etc/nginx/nginx.conf
systemctl start httpd mariadb nginx

# auto renew