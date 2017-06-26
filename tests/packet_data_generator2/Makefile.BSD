# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# OVS: openvswitch installed directory  (used to look for libraries)
# OVS_SRC: openvswitch source directory

OVS?=${HOME}/ovs
OVS_SRC?=/disks/774373a2-e180-11e3-9fa1-08606e7f74e7/git/openvswitch

CPPFLAGS+=-I${OVS}/include -I${OVS_SRC}
LDFLAGS+=-L${OVS}/lib -Wl,-R${OVS}/lib -lofproto -lopenvswitch

PROG=gen
NOMAN=

all: generate

generate: ${PROG}
	${_MKMSG} "generate packet_data"
	cd ${.CURDIR} && ${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
