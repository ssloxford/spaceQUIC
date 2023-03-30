#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo "Usage:"
    echo "    ./run-ground CONTAINER_ID"
    echo ""
    echo "The container ID can be found using \"docker ps\"."
    exit 1
fi

CONTAINER_ID=$1

docker exec $CONTAINER_ID /util/entrypoint-ground.sh
