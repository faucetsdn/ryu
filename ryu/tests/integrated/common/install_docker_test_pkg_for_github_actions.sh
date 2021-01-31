#!/bin/bash
set -ex

RYU_PATH=`dirname $0`

source  ${RYU_PATH}/install_docker_test_pkg_common.sh

init_variables
process_options "$@"

sudo apt-get update
install_depends_pkg
