import os
PKGDATADIR = os.environ.get("OVS_PKGDATADIR", """/usr/share/openvswitch""")
RUNDIR = os.environ.get("OVS_RUNDIR", """/var/run/openvswitch""")
LOGDIR = os.environ.get("OVS_LOGDIR", """/var/log/openvswitch""")
BINDIR = os.environ.get("OVS_BINDIR", """/usr/bin""")

DBDIR = os.environ.get("OVS_DBDIR")
if not DBDIR:
    sysconfdir = os.environ.get("OVS_SYSCONFDIR")
    if sysconfdir:
        DBDIR = "%s/openvswitch" % sysconfdir
    else:
        DBDIR = """/etc/openvswitch"""
