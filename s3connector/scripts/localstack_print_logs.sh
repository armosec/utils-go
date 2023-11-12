#!/bin/bash
cr='docker'
PODMAN_EXISTS=$(which podman)
RET_VAL=$?
if [ $RET_VAL -eq '0' ]; then
    echo "podman exists."
    cr='podman'
fi
$cr ps -a
$cr logs %s