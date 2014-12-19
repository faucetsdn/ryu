:orphan:

ryu manual page
===============

Synopsis
--------
**ryu** [-h] [--config-dir DIR] [--config-file PATH] [--version] [subcommand] ...

Description
-----------
:program:`ryu` is the executable for Ryu applications. ryu loads a sub-module
corresponding to the sub-command and run it. 'run' sub-command is an
equivalent to ryu-manager.

Ryu is a component-based software defined networking framework. Ryu
provides software components with well defined API that make it easy for
developers to create new network management and control applications.
Ryu supports various protocols for managing network devices, such as
OpenFlow, Netconf, OF-config, etc. About OpenFlow, Ryu supports fully
1.0, 1.2, 1.3, 1.4 and Nicira Extensions.

Options
-------
subcommand
    [rpc-cli|run|of-config-cli]

subcommand_args
    subcommand specific arguments

-h, --help
    show this help message and exit

--config-dir DIR
    Path to a config directory to pull \*.conf files from.
    This file set is sorted, so as to provide a predictable
    parse order if individual options are over-ridden. The
    set is parsed after the file(s) specified via previous
    --config-file, arguments hence over-ridden options in
    the directory take precedence.

--config-file PATH
    Path to a config file to use. Multiple config files can
    be specified, with values in later files taking
    precedence. The default files used are: None

--version
    show program's version number and exit
