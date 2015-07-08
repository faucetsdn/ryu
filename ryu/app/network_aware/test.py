import time


def _monitor():
    i = 0
    while True:
        print "show topo"
        if i == 5:
            print "get_topo"
            i = 0
        time.sleep(5)
        i = i + 1

def monitor():
    while True:
        print "show topo"
        print "get_topo"
        time.sleep(5)

monitor()
