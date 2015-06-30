# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at valinux co jp>
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

# based on netconf.xsd

# rpc
RPC = 'rpc'
MESSAGE_ID = 'message-id'      # message-id attribute

# error
TRANSPORT = 'transport'
PROTOCOL = 'protocol'
APPLICATION = 'application'

# error-tag
IN_USE = 'in-use'
INVALID_VALUE = 'invalid-value'
TOO_BIG = 'too-big'
MISSING_ATTRIBUTE = 'missing-attribute'
BAD_ATTRIBUTE = 'bad-attribute'
UNKNOWN_ATTRIBUTE = 'unknown-attribute'
MISSING_ELEMENT = 'missing-element'
BAD_ELEMENT = 'bad-element'
UNKNOWN_ELEMENT = 'unknown-element'
UNKNOWN_NAMESPACE = 'unknown-namespace'
ACCESS_DENIED = 'access-denied'
LOCK_DENIED = 'lock-denied'
RESOURCE_DENIED = 'resource-denied'
ROLLBACK_FAILED = 'rollback-failed'
DATA_EXISTS = 'data-exists'
DATA_MISSING = 'data-missing'
OPERATION_NOT_SUPPORTED = 'operation-not-supported'
OPERATION_FAILED = 'operation-failed'
PARTIAL_OPERATION = 'partial-operation'
MALFORMED_MESSAGE = 'malformed-message'

# error-severity
ERROR = 'error'
WARNING = 'warning'

# error-info
# bad-attribute, bad-element and ok-element are defined above
# BAD_ATTRIBUTE = 'bad-attribute'
# BAD_ELEMENT = 'bad-element'
# OK_ELEMENT = 'ok-element'
ERR_ELEMENT = 'err-element'
NOOP_ELEMENT = 'noop-element'
BAD_NAMESPACE = 'bad-namespace'

# rpc-error
ERROR_TYPE = 'error-type'
ERROR_TAG = 'error-tag'
ERROR_SEVERITY = 'error-severity'
ERROR_APP_TAG = 'error-app-tag'
ERROR_PATH = 'error-path'
ERROR_MESSAGE = 'error-message'
ERROR_INFO = 'error-info'

# edit-operation
OPERATION = 'operation'         # operation attribute
MERGE = 'merge'
REPLACE = 'replace'
CREATE = 'create'
DELETE = 'delete'
REMOVE = 'remove'

# default-operation
# merge and replace are defined above
# MERGE = 'merge'
# REPLACE = 'replace'
NONE = 'none'
DEFAULT_OPERATION = 'default-operation'

# rpc-reply
OK = 'ok'
RPC_REPLY = 'rpc-reply'

# data-inline
DATA = 'data'
RPC_ERROR = 'rpc-error'

# rpc-operation
RPCOPERATION = 'rpcOperation'

# rpc-response
RPCRESPONSE = 'rpcResponse'
HELLO = 'hello'
CAPABILITIES = 'capabilities'
CAPABILITY = 'capability'

# config-inline
CONFIG = 'config'

# config-name
CONFIG_NAME = 'config-name'
STARTUP = 'startup'
CANDIDATE = 'candidate'
RUNNING = 'running'

# config-uri
URL = 'url'

# rpc-operation-source
SOURCE = 'source'

# rpc-operation-target
TARGET = 'target'

# filter
SUBTREE = 'subtree'
XPATH = 'xpath'

# filter-inline
TYPE = 'type'           # type attribute
FILTER = 'filter'

# test-option
TEST_THEN_SET = 'test-then-set'
SET = 'set'
TEST_OPTION = 'test-option'

# error-option
STOP_ON_ERROR = 'stop-on-error'
IGNORE_ERROR = 'ignore-error'
ROLLBACK_ON_ERROR = 'rollback-on-error'
ERROR_OPTION = 'error-option'

# get
GET = 'get'

# get-config
GET_CONFIG = 'get-config'

# edit-config
EDIT_CONFIG = 'edit-config'

# copy-config
COPY_CONFIG = 'copy-config'

# delete-config
DELETE_CONFIG = 'delete-config'

# lock
LOCK = 'lock'

# unlock
UNLOCK = 'unlock'

# validate
VALIDATE = 'validate'

# commit
CONFIRMED = 'confirmed'
CONFIRM_TIMEOUT = 'confirm-timeout'
PERSIST = 'persist'
PERSIST_ID = 'persist-id'
COMMIT = 'commit'

# cancel-commit
# persist-id is defined above
# PERSIST_ID = 'persist-id'
CANCEL_COMMIT = 'cancel-commit'

# discard-changes
DISCARD_CHANGES = 'discard-changes'

# close-session
CLOSE_SESSION = 'close-session'

# kill-session
KILL_SESSION = 'kill-session'
