set -e
cd microservices/socialapp
git pull
docker compose build
docker compose up -d --remove-orphans
docker builder prune -f
/usr/local/go/bin/go clean -modcache 

cd ..

cd urlshortener
git pull
docker compose build
docker compose up -d --remove-orphans
docker builder prune -f
/usr/local/go/bin/go clean -modcache 
