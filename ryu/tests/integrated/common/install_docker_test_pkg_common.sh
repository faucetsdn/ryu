#!/bin/bash
set -ex

function init_variables {
    APTLINE_DOCKER=0
    DIR_BASE=/tmp
    SUDO_PIP=""
}

function process_options {
    local max
    local i
    max=$#
    i=1
    while [ $i -le $max ]; do
        case "$1" in
            -a|--add-docker-aptline)
                APTLINE_DOCKER=1
                ;;
            -d|--download-dir)
                shift; ((i++))
                DIR_BASE=$1
                ;;
            -s|--sudo-pip)
                SUDO_PIP=sudo
                ;;
        esac
        shift; ((i++))
    done
}

function install_depends_pkg {
    sudo rm -rf $DIR_BASE/pipework
    git clone https://github.com/jpetazzo/pipework.git $DIR_BASE/pipework
    sudo install -m 0755 $DIR_BASE/pipework/pipework /usr/local/bin/pipework
    $SUDO_PIP pip install pycrypto nsenter
}
