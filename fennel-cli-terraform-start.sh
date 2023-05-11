 #!/bin/bash
sudo apt-get update
sudo apt-get install -y docker.io
gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin us-east1-docker.pkg.dev
docker run -dit -p 9031:9031 --name fennel-cli us-east1-docker.pkg.dev/whiteflag-0/fennel-docker-registry/fennel-cli:latest
docker exec -it fennel-cli sh
cd /app/target/release/build
cargo run --bin fennel-cli start-api