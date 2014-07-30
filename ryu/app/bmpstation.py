import socket
import logging
logging.basicConfig(level=logging.DEBUG)

from ryu.base import app_manager

from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.lib.packet.bmp import *

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 11019


class BMPStation(app_manager.RyuApp):
    def __init__(self):
        super(BMPStation, self).__init__()
        self.name = 'bmpstation'

    def start(self):
        super(BMPStation, self).start()

        return hub.spawn(StreamServer((SERVER_HOST, SERVER_PORT),
                                      self.loop).serve_forever)

    def loop(self, sock, addr):
        logging.debug("started bmp loop.")
        self.is_active = True

        buf = bytearray()
        required_len = BMPMessage._HDR_LEN

        while self.is_active:
            buf = sock.recv(BMPMessage._HDR_LEN)
            if len(buf) == 0:
                self.is_active = False
                break

            _, len_, _ = BMPMessage.parse_header(buf)

            body = sock.recv(len_ - BMPMessage._HDR_LEN)
            if len(body) == 0:
                self.is_active = False
                break

            msg, rest = BMPMessage.parser(buf + body)
            assert len(rest) == 0
            print msg, '\n'
