*******************
BGP speaker library
*******************

Introduction
============

Ryu BGP speaker library helps you to enable your code to speak BGP
protocol. The library supports ipv4, ipv4 vpn, and ipv6 vpn address
families.

Example
=======

The following simple code creates a BGP instance with AS number 64512
and Router ID 10.0.0.1. It tries to establish a bgp session with a
peer (its IP is 192.168.177.32 and the AS number is 64513). The
instance advertizes some prefixes.

.. code-block:: python

    import eventlet

    # BGPSpeaker needs sockets patched
    eventlet.monkey_patch()

    # initialize a log handler
    # this is not strictly necessary but useful if you get messages like:
    #    No handlers could be found for logger "ryu.lib.hub"
    import logging
    import sys
    log = logging.getLogger()
    log.addHandler(logging.StreamHandler(sys.stderr))

    from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker

    def dump_remote_best_path_change(event):
        print 'the best path changed:', event.remote_as, event.prefix,\
            event.nexthop, event.is_withdraw

    def detect_peer_down(remote_ip, remote_as):
        print 'Peer down:', remote_ip, remote_as

    if __name__ == "__main__":
        speaker = BGPSpeaker(as_number=64512, router_id='10.0.0.1',
                             best_path_change_handler=dump_remote_best_path_change,
                             peer_down_handler=detect_peer_down)

        speaker.neighbor_add('192.168.177.32', 64513)
	# uncomment the below line if the speaker needs to talk with a bmp server.
	# speaker.bmp_server_add('192.168.177.2', 11019)
        count = 1
        while True:
            eventlet.sleep(30)
            prefix = '10.20.' + str(count) + '.0/24'
            print "add a new prefix", prefix
            speaker.prefix_add(prefix)
            count += 1
            if count == 4:
                speaker.shutdown()
                break
