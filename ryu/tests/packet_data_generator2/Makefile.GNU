# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# OVS_SRC: openvswitch source directory
# OVS_INC: openvswitch include directory
# OVS_LIB: openvswitch library directory

OVS_SRC=${HOME}/ovs
OVS_INC=/usr/local/include/openvswitch
OVS_LIB=/usr/local/lib

CPPFLAGS=-std=gnu99 -I${OVS_SRC} -I${OVS_INC}
LDFLAGS=-L${OVS_LIB} -Wl,-R${OVS_LIB} -lofproto -lopenvswitch -lpthread -lssl -lrt -lm -lcrypto

PROG=gen
NOMAN=

all: generate

gen: gen.c
	${CC} $^ ${CPPFLAGS} ${LDFLAGS} -o $@

generate: ${PROG}
	./${PROG}

clean:
	rm ${PROG}
