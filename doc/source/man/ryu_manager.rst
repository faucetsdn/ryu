:orphan:

ryu-manager manual page
=======================


Synopsis
--------
**ryu-manager** [-h]
[--app-lists APP_LISTS] [--ca-certs CA_CERTS]
[--config-dir DIR] [--config-file PATH]
[--ctl-cert CTL_CERT] [--ctl-privkey CTL_PRIVKEY]
[--default-log-level DEFAULT_LOG_LEVEL] [--explicit-drop]
[--install-lldp-flow] [--log-config-file LOG_CONFIG_FILE]
[--log-dir LOG_DIR] [--log-file LOG_FILE]
[--log-file-mode LOG_FILE_MODE]
[--neutron-admin-auth-url NEUTRON_ADMIN_AUTH_URL]
[--neutron-admin-password NEUTRON_ADMIN_PASSWORD]
[--neutron-admin-tenant-name NEUTRON_ADMIN_TENANT_NAME]
[--neutron-admin-username NEUTRON_ADMIN_USERNAME]
[--neutron-auth-strategy NEUTRON_AUTH_STRATEGY]
[--neutron-controller-addr NEUTRON_CONTROLLER_ADDR]
[--neutron-url NEUTRON_URL]
[--neutron-url-timeout NEUTRON_URL_TIMEOUT]
[--noexplicit-drop] [--noinstall-lldp-flow]
[--noobserve-links] [--nouse-stderr] [--nouse-syslog]
[--noverbose] [--observe-links]
[--ofp-listen-host OFP_LISTEN_HOST]
[--ofp-ssl-listen-port OFP_SSL_LISTEN_PORT]
[--ofp-tcp-listen-port OFP_TCP_LISTEN_PORT] [--use-stderr]
[--use-syslog] [--verbose] [--version]
[--wsapi-host WSAPI_HOST] [--wsapi-port WSAPI_PORT]
[--test-switch-dir TEST-SWITCH_DIR]
[--test-switch-target TEST-SWITCH_TARGET]
[--test-switch-tester TEST-SWITCH_TESTER]
[app [app ...]]

Description
-----------
:program:`ryu-manager` is the executable for Ryu applications. ryu-manager
loads Ryu applications and run it.

Ryu is a component-based software defined networking framework. Ryu
provides software components with well defined API that make it easy for
developers to create new network management and control applications.
Ryu supports various protocols for managing network devices, such as
OpenFlow, Netconf, OF-config, etc. About OpenFlow, Ryu supports fully
1.0, 1.2, 1.3, 1.4 and Nicira Extensions.

Options
-------
app
    application module name to run

-h, --help
    show this help message and exit

--app-lists APP_LISTS
    application module name to run

--ca-certs CA_CERTS
    CA certificates

--config-dir DIR
    Path to a config directory to pull \*.conf files from.
    This file set is sorted, so as to provide a
    predictable parse order if individual options are
    over-ridden. The set is parsed after the file(s)
    specified via previous --config-file, arguments hence
    over-ridden options in the directory take precedence.

--config-file PATH
    Path to a config file to use. Multiple config files
    can be specified, with values in later files taking
    precedence. The default files used are: None

--ctl-cert CTL_CERT
    controller certificate

--ctl-privkey CTL_PRIVKEY  
    controller private key

--default-log-level DEFAULT_LOG_LEVEL  
    default log level

--explicit-drop
    link discovery: explicitly drop lldp packet in

--install-lldp-flow
    link discovery: explicitly install flow entry to send
    lldp packet to controller

--log-config-file LOG_CONFIG_FILE
    Path to a logging config file to use

--log-dir LOG_DIR
    log file directory

--log-file LOG_FILE
    log file name

--log-file-mode LOG_FILE_MODE  
    default log file permission

--neutron-admin-auth-url NEUTRON_ADMIN_AUTH_URL  
    auth url for connecting to neutron in admin context

--neutron-admin-password NEUTRON_ADMIN_PASSWORD  
    password for connecting to neutron in admin context

--neutron-admin-tenant-name NEUTRON_ADMIN_TENANT_NAME  
    tenant name for connecting to neutron in admin context

--neutron-admin-username NEUTRON_ADMIN_USERNAME  
    username for connecting to neutron in admin context

--neutron-auth-strategy NEUTRON_AUTH_STRATEGY  
    auth strategy for connecting to neutron in admincontext

--neutron-controller-addr NEUTRON_CONTROLLER_ADDR  
    openflow method:address:port to set controller ofovs bridge

--neutron-url NEUTRON_URL  
    URL for connecting to neutron

--neutron-url-timeout NEUTRON_URL_TIMEOUT  
    timeout value for connecting to neutron in seconds

--noexplicit-drop
    The inverse of --explicit-drop

--noinstall-lldp-flow  
    The inverse of --install-lldp-flow

--noobserve-links
    The inverse of --observe-links

--nouse-stderr
    The inverse of --use-stderr

--nouse-syslog
    The inverse of --use-syslog

--noverbose
    The inverse of --verbose

--observe-links
    observe link discovery events.

--ofp-listen-host OFP_LISTEN_HOST  
    openflow listen host

--ofp-ssl-listen-port OFP_SSL_LISTEN_PORT  
    openflow ssl listen port

--ofp-tcp-listen-port OFP_TCP_LISTEN_PORT  
    openflow tcp listen port

--use-stderr
    log to standard error

--use-syslog
    output to syslog

--verbose
    show debug output

--version
    show program's version number and exit

--wsapi-host WSAPI_HOST  
    webapp listen host

--wsapi-port WSAPI_PORT  
    webapp listen port
  
--test-switch-dir TEST-SWITCH_DIR  
    test files directory

--test-switch-target TEST-SWITCH_TARGET  
    target sw dp-id

--test-switch-tester TEST-SWITCH_TESTER  
    tester sw dp-id
