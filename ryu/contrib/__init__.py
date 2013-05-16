#!/usr/bin/env python
#
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
# Adjust module loading path for third party libraries

import os
import sys

_original_sys_path = list(sys.path)

for path in __path__:
    if path in sys.path:
        sys.path.remove(path)
    path = os.path.abspath(path)
    if path in sys.path:
        sys.path.remove(path)
    sys.path.insert(0, path)  # prioritize our own copy than system's

def import_system(module):
    """import a system module
    """
    saved_path = sys.path
    try:
        sys.path = _original_sys_path
        __import__(module)
    finally:
        sys.path = saved_path
    return sys.modules[module]
