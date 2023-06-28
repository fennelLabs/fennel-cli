map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream websocket {
    server 127.0.0.1:9031;
}

server {
    server_name bitwise.fennellabs.com;

    location / {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $server_name;
        proxy_set_header Proxy "";
        proxy_set_header X-Real-IP $remote_addr; 
		proxy_set_header X-Forwarded-Proto $scheme; 
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
    }
}
