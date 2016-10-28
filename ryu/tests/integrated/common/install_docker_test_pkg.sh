#!/bin/bash
set -ex

RYU_PATH=`dirname $0`

source  ${RYU_PATH}/install_docker_test_pkg_common.sh

function add_docker_aptline {
    sudo apt-get update
    if ! apt-cache search docker-engine | grep docker-engine; then
        VER=`lsb_release -r`
        if echo $VER | grep 12.04; then
            REL_NAME=precise
        elif echo $VER | grep 14.04; then
            REL_NAME=trusty
        elif echo $VER | grep 15.10; then
            REL_NAME=wily
        elif echo $VER | grep 16.04; then
            REL_NAME=xenial
        else
            retrun 1
        fi
        RELEASE=ubuntu-$REL_NAME
        sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
        sudo sh -c "echo deb https://apt.dockerproject.org/repo $RELEASE main > /etc/apt/sources.list.d/docker.list"
    fi
}

init_variables
process_options "$@"

if [ $APTLINE_DOCKER -eq 1 ]; then
    add_docker_aptline
fi

sudo apt-get update
if apt-cache search docker-engine | grep docker-engine; then
    DOCKER_PKG=docker-engine
else
    DOCKER_PKG=docker.io
fi
sudo apt-get install -y $DOCKER_PKG
install_depends_pkg
