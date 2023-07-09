 #!/bin/bash
sudo apt-get update
sudo apt-get install -y docker.io nginx snapd
sudo snap install core && sudo snap refresh core
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
gsutil cat gs://whiteflag-0-admin/fennel-nginx-conf-cli.sh > /etc/nginx/sites-enabled/default
sudo systemctl enable nginx
sudo systemctl start nginx
sudo certbot --nginx --non-interactive --agree-tos --email info@fennellabs.com --domains bitwise.fennellabs.com
sudo systemctl restart nginx
gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin us-east1-docker.pkg.dev
docker run -dt -p 9031:9031 --name fennel-cli us-east1-docker.pkg.dev/whiteflag-0/fennel-docker-registry/fennel-cli:latest
docker exec fennel-cli /app/target/release/fennel-cli start-api
