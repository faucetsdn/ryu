# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

"""
Database implementation for Zebra protocol service.
"""

from __future__ import absolute_import

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ryu import cfg

# Configuration parameters for Zebra service
CONF = cfg.CONF['zapi']

# Connect to database
ENGINE = create_engine(CONF.db_url)

Session = sessionmaker(bind=ENGINE)
"""
Session class connecting to database
"""

# Create all tables
from . import base
from . import interface
from . import route
base.Base.metadata.create_all(ENGINE)
