#!/bin/bash

docker=$(which docker)

$docker run -d --name go-dev -v ./Code:/workdir -v /var/run/docker.sock:/var/run/docker.sock go-env