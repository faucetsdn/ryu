"""
Parsing libpcap and reading/writing PCAP file.
Reference source: http://wiki.wireshark.org/Development/LibpcapFileFormat


                  Libpcap File Format

                +---------------------+
                |                     |
                |     Global Header   |
                |                     |
                +---------------------+
                |     Packet Header   |
                +---------------------+
                |     Packet Data     |
                +---------------------+
                |     Packet Header   |
                +---------------------+
                |     Packet Data     |
                +---------------------+
                |          ...
                +---------------- ...


Sample usage of dump packets:

    from ryu.lib import pcaplib

    class SimpleSwitch13(app_manager.RyuApp):
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            super(SimpleSwitch13, self).__init__(*args, **kwargs)
            self.mac_to_port = {}

            # Creating an instance with a PCAP filename
            self.pcap_pen = Writer(open('mypcap.pcap', 'wb'))

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
            msg = ev.msg

            # Dump the data packet into PCAP file
            self.pcap_pen.write_pkt(msg.data)

            pkt = packet.Packet(msg.data)

Sample usage of reading PCAP files:

    from ryu.lib import pcaplib
    from ryu.lib.packet import packet

    frame_count = 0
    # Using the Reader iterator that yields packets in PCAP file
    for ts, buf in pcaplib.Reader(open('test.pcap', 'rb')):
        frame_count += 1
        pkt = packet.Packet(buf)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        # print frames count, timestamp, ethernet src, ethernet dst
        # and raw packet.
        print frame_count, ts, dst, src, pkt

"""

import six
import struct
import sys
import time


class PcapFileHdr(object):
    """
    Global Header
    typedef struct pcap_hdr_s {
                guint32 magic_number;   /* magic number */
                guint16 version_major;  /* major version number */
                guint16 version_minor;  /* minor version number */
                gint32  thiszone;       /* GMT to local correction */
                guint32 sigfigs;        /* accuracy of timestamps */
                guint32 snaplen;        /* max length of captured packets,
                                           in octets */
                guint32 network;        /* data link type */
    } pcap_hdr_t;

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Magic Number                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Version Major          |        Version Minor          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Thiszone                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Sigfigs                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Snaplen                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Network                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                File Format
    """
    _FILE_HDR_FMT = None

    def __init__(self, magic=b'\xd4\xc3\xb2\xa1', version_major=2,
                 version_minor=4, thiszone=0, sigfigs=0, snaplen=0,
                 linktype=0):
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.linktype = linktype

    @classmethod
    def parser(cls, buf):
        if buf[:4] == b'\xa1\xb2\xc3\xd4':
            # Big Endian
            cls._FILE_HDR_FMT = '>IHHIIII'
            byteorder = '>'
        elif buf[:4] == b'\xd4\xc3\xb2\xa1':
            # Little Endian
            cls._FILE_HDR_FMT = '<IHHIIII'
            byteorder = '<'
        else:
            raise Exception('Invalid pcap file.')

        (magic, version_major, version_minor, thiszone, sigfigs,
         snaplen, linktype) = struct.unpack_from(cls._FILE_HDR_FMT, buf)

        hdr = cls(magic, version_major, version_minor, thiszone, sigfigs,
                  snaplen, linktype)
        return hdr, byteorder

    def serialize(self, fmt):
        return struct.pack(fmt, self.magic, self.version_major,
                           self.version_minor, self.thiszone,
                           self.sigfigs, self.snaplen, self.linktype)


class PcapPktHdr(object):
    """
    Record (Packet) Header
    typedef struct pcaprec_hdr_s {
            guint32 ts_sec;       /* timestamp seconds */
            guint32 ts_usec;      /* timestamp microseconds */
            guint32 incl_len;     /* number of octets of packet
                                     saved in file */
            guint32 orig_len;     /* actual length of packet */
    } pcaprec_hdr_t;

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Timestamp Seconds                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Timestamp Microseconds                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Number of octets of saved in file            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Actual length of packet                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        Record (Packet) Header Format
    """

    _PKT_HDR_FMT = None

    def __init__(self, ts_sec=0, ts_usec=0, incl_len=0, orig_len=0):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

    @classmethod
    def parser(cls, byteorder, buf):
        if not buf:
            raise IndexError('No data')
        cls._PKT_HDR_FMT = byteorder + 'IIII'
        PKT_HDR_LEN = struct.calcsize(cls._PKT_HDR_FMT)

        (ts_sec, ts_usec, incl_len,
         orig_len) = struct.unpack_from(cls._PKT_HDR_FMT, buf)

        hdr = cls(ts_sec, ts_usec, incl_len, orig_len)
        # print repr(buf[0:16])
        return hdr, buf[PKT_HDR_LEN:PKT_HDR_LEN + incl_len]

    def serialize(self, fmt):
        return struct.pack(fmt, self.ts_sec, self.ts_usec,
                           self.incl_len, self.orig_len)


class Reader(object):
    _FILE_HDR_FMT = '>IHHIIII'
    _PKT_HDR_FMT = '>IIII'

    _PKT_HDR_LEN = struct.calcsize(_PKT_HDR_FMT)
    _FILE_HDR_FMT_LEN = struct.calcsize(_FILE_HDR_FMT)

    def __init__(self, file_obj):
        self._fp = file_obj
        # self.__filename = filename
        self._file_byteorder = None
        self._hdr_data = None
        self.incl_len_pos = 0

    def __iter__(self):
        buf = self._fp.read(Reader._FILE_HDR_FMT_LEN)
        # Only Read PCAP file from 0 to 24th byte
        (filehdr, self._file_byteorder) = PcapFileHdr.parser(buf)

        # self._fp.seek(Reader._FILE_HDR_FMT_LEN)

        # Read PCAP file from 24th byte to EOF
        self._hdr_data = self._fp.read()
        self._fp.close()

        return self

    def next(self):
        try:
            pkt_hdr, pkt_data = PcapPktHdr.parser(self._file_byteorder,
                                                  self._hdr_data
                                                  [self.incl_len_pos:])

            next_pos = pkt_hdr.incl_len + Reader._PKT_HDR_LEN
            self.incl_len_pos += next_pos
        except IndexError:
            raise StopIteration

        return float(pkt_hdr.ts_sec + (pkt_hdr.ts_usec / 1e6)), pkt_data


class Writer(object):
    def __init__(self, file_obj, snaplen=65535, linktype=1):
        self._f = file_obj
        self._write_pcap_file_hdr(snaplen, linktype)

    def _write_pcap_file_hdr(self, snaplen, linktype):
        if sys.byteorder == 'little':
            pcap_file_hdr = PcapFileHdr(magic=0xa1b2c3d4,
                                        snaplen=snaplen,
                                        linktype=linktype)
            p = pcap_file_hdr.serialize(fmt='<IHHIIII')
        else:
            pcap_file_hdr, byteorder = PcapFileHdr(magic=0xd4c3b2a1,
                                                   naplen=snaplen,
                                                   linktype=linktype)
            p = pcap_file_hdr.serialize(fmt='>IHHIIII')
        self._f.write(str(p))

    def _write_pkt_hdr(self, ts, buf_str_len):
        sec = int(ts)
        if sec == 0:
            usec = 0
        else:
            usec = int(ts * 1e6) % int(ts)

        if sys.byteorder == 'little':
            # usec = int(ts * 1e6) % int(ts)
            # old_usec = int((float(ts) - int(ts)) * 1e6)
            pc_pkt_hdr = PcapPktHdr(ts_sec=sec,
                                    ts_usec=usec,
                                    incl_len=buf_str_len,
                                    orig_len=buf_str_len)
            p = pc_pkt_hdr.serialize(fmt='<IIII')
        else:
            pc_pkt_hdr = PcapPktHdr(ts_sec=sec,
                                    ts_usec=usec,
                                    incl_len=buf_str_len,
                                    orig_len=buf_str_len)
            p = pc_pkt_hdr.serialize(fmt='>IIII')
        self._f.write(str(p))

    def write_pkt(self, buf, ts=None):
        if ts is None:
            ts = time.time()

        buf_str = six.binary_type(buf)
        buf_str_len = len(buf_str)
        self._write_pkt_hdr(ts, buf_str_len)
        self._f.write(buf_str)

    def __del__(self):
        self._f.close()
