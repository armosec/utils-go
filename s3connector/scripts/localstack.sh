#!/bin/bash

cr='docker'
PODMAN_EXISTS=$(which podman)
RET_VAL=$?

if [ $RET_VAL -eq '0' ]; then
    echo "podman exists."
    cr='podman'
else 
    echo "podman does not exist. using docker"
fi

app_port=${2:-4566} # Use this as default port if no argument is provided

admin_port=${3:-4566} # Use this as default port if no argument is provided
echo "All arguments: $@"

app_port=%d
container_name=%s

echo "Starting localstack on port $app_port and admin port $admin_port"

$cr run --name=$container_name -d -p $app_port:4566 -e SERVICES=s3 --memory=512mb docker.io/localstack/localstack@sha256:37b0ba556f4ecc4569e39095faf5e12cf46e96718fa12bc69380ac0f9cd83378
