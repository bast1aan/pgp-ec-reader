#!/bin/sh

docker build -t pgpreader -f Dockerfile .

container=$(docker create pgpreader)
mkdir ./docker-build
docker cp $container:/srv/target/ ./docker-build/
docker rm $container
