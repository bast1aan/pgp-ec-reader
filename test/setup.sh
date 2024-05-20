#!/bin/sh -xe

cd ..
./build-with-docker.sh
ln -s docker-build/target

echo Done. You should be able to run ./tests.sh now.
