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
    from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
        
    def dump_remote_best_path_change(event):
        print 'the best path changed:', event.remote_as, event.prefix,\
            event.nexthop, event.is_withdraw

    if __name__ == "__main__":
        speaker = BGPSpeaker(as_number=64512, router_id='10.0.0.1',
                             best_path_change_handler=dump_remote_best_path_change)
        
        speaker.neighbor_add('192.168.177.32', 64513)
    
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
