#!/usr/bin/env python2
#
# Email: Hagen Paul Pfeifer <hagen@jauu.net>
# URL: http://research.protocollabs.com/captcp/

# Captcp is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Captcp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Captcp. If not, see <http://www.gnu.org/licenses/>.


import sys
import os
import logging
import dpkt
import socket
import struct
import inspect
import math
import time
import datetime
import subprocess
import select
import re
import shutil
import distutils.dir_util
import string
import numpy
import binascii

# Required debian packages:
#   python-dpkt

# Suggested debian packages:
#   python-cairo

# Optional debian packages:
#   python-geoip
#   python-numpy


__programm__ = "captcp"
__author__   = "Hagen Paul Pfeifer"
__version__  = "1.7"
__license__  = "GPLv3"

# Exported statistics constant

STATISTIC_LABELS = ["packets-packets", "duration-timedelta", "link-layer-byte",
    "network-layer-byte", "transport-layer-byte", "application-layer-byte",
    "link-layer-throughput-bitsecond", "network-layer-throughput-bitsecond",
    "transport-layer-throughput-bitsecond", "application-layer-throughput-bitsecond",
    "rexmt-data-bytes", "rexmt-data-packets", "rexmt-bytes-percent",
    "rexmt-packets-percent", "pure-ack-packets", "push-flag-set-packets",
    "ece-flag-set-packets", "cwr-flag-set-packets", "tl-ps-min",
    "tl-ps-max", "tl-ps-avg", "tl-ps-median", "tl-ps-std", "tl-iats-min",
    "tl-iats-max", "tl-iats-avg", "tl-iats-std"]

# custom exceptions
class ArgumentException(Exception): pass
class InternalException(Exception): pass
class SkipProcessStepException(Exception): pass
class PacketNotSupportedException(Exception): pass

# TCP flag constants
TH_URG = dpkt.tcp.TH_URG
TH_ACK = dpkt.tcp.TH_ACK
TH_PSH = dpkt.tcp.TH_PUSH
TH_RST = dpkt.tcp.TH_RST
TH_SYN = dpkt.tcp.TH_SYN
TH_FIN = dpkt.tcp.TH_FIN
TH_ECE = dpkt.tcp.TH_ECE
TH_CWR = dpkt.tcp.TH_CWR
# "Robust Explicit Congestion Notification (ECN)
# Signaling with Nonces" (RFC 3540) specifies an
# additional ECN Flag: NS which is out of the 8 bit
# flags section, shared with header length field. I
# emailed Jon Oberheide to get some valuable solutions.
#
# See http://tools.ietf.org/html/rfc3540#section-9

# Protocols
TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP

# Units (bit):
# kilobit (kbit) 10^3 - kibibit (Kibit) 2^10
# megabit (Mbit) 10^6 - mebibit (Mibit) 2^20
# gigabit (Gbit) 10^9 - gibibit (Gibit) 2^30
#
# Units (byte):
# kilobyte (kB) 10^3 - kibibyte (KiB) 2^10
# megabyte (MB) 10^6 - mebibyte (MiB) 2^20
# gigabyte (GB) 10^9 - gibibyte (GiB) 2^30


class ExitCodes:
    EXIT_SUCCESS     = 0
    EXIT_ERROR       = 1
    EXIT_CMD_LINE    = 2
    EXIT_ENVIRONMENT = 3
    EXIT_PLATFORM    = 4


class Info:
    ETHERNET_HEADER_LEN = 14


class U:
    """ Utility module, to collect usefull functionality
    needed by several other classes. We name it U to make it short
    and non bloated"""

    @staticmethod
    def percent(a, b):
        if b == 0: return 0.0
        return float(a) / b * 100

    @staticmethod
    def ts_tofloat(ts):
        return float(ts.seconds) + ts.microseconds / 1E6 + ts.days * 86400

    @staticmethod
    def add_colons_to_mac( mac_addr ) :
        mac_addr = binascii.hexlify(mac_addr)
        s = list()
        for i in range(12/2) :  # mac_addr should always be 12 chars, we work in groups of 2 chars
            s.append( mac_addr[i*2:i*2+2] )
        r = ":".join(s)     # I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
        return r



class Converter:

    def num_to_dotted_quad(n):
        "convert long int to dotted quad string"
        return socket.inet_ntoa(struct.pack('I', n))
    num_to_dotted_quad = staticmethod(num_to_dotted_quad)

    def dpkt_addr_to_string(addr):
        if len(addr) == 16:
            # IPv6
            # FIXME: inet_ntop is UNIX only according to the python doc
            return socket.inet_ntop(socket.AF_INET6, addr)
        else:
            # IPv4
            iaddr = int(struct.unpack('I', addr)[0])
            return Converter.num_to_dotted_quad(iaddr)

    dpkt_addr_to_string  = staticmethod(dpkt_addr_to_string)




class PcapParser:

    def __init__(self, pcap_file_path, filters):
        self.logger = logging.getLogger()
        self.pcap_file = False
        self.filters = filters

        try:
            self.pcap_file = open(pcap_file_path)
        except IOError:
            self.logger.error("Cannot open pcap file: %s" % (pcap_file_path))
            sys.exit(ExitCodes.EXIT_ERROR)
        self.pc = dpkt.pcap.Reader(self.pcap_file)
        try:
            self.decode = {
                dpkt.pcap.DLT_LOOP:      dpkt.loopback.Loopback,
                dpkt.pcap.DLT_NULL:      dpkt.loopback.Loopback,
                dpkt.pcap.DLT_EN10MB:    dpkt.ethernet.Ethernet,
                dpkt.pcap.DLT_IEEE802:   dpkt.ethernet.Ethernet,
                dpkt.pcap.DLT_PPP:       dpkt.ppp.PPP,
                dpkt.pcap.DLT_LINUX_SLL: dpkt.sll.SLL
            }[self.pc.datalink()]
        except KeyError:
            self.logger.error("Packet link type not know (%d)! "
                              "Interpret at Ethernet now - but be carefull!" % (
                              self.pc.datalink()))
            self.decode = dpkt.ethernet.Ethernet

    def __del__(self):
        if self.pcap_file:
            self.pcap_file.close()

    def register_callback(self, callback):
        self.callback = callback

    def packet_len_error(self, snaplen, packet_len):
        self.logger.critical("Captured data was too short (packet: %d, snaplen: %d)"
                            " - please recapture with snaplen of 0: infinity" %
                             (packet_len, snaplen))


    def run(self):
        try:
            for ts, pkt in self.pc:
                if self.pc.snaplen < len(pkt):
                    self.packet_len_error(self.pc.snaplen, len(pkt))
                    sys.exit(1)
                packet = self.decode(pkt)
                dt = datetime.datetime.fromtimestamp(ts)
                
                # Filter packet according to mac addresses
                strSrcMac = U.add_colons_to_mac(packet.src)
                strDstMac = U.add_colons_to_mac(packet.dst)

                noneFilter = [None, None]
                srcDstFilter = [strSrcMac, strDstMac]
                srcFilter = [strSrcMac, None]
                dstFilter = [None, strDstMac]

                if (noneFilter in self.filters or
                        srcFilter in self.filters or 
                        dstFilter in self.filters or 
                        srcDstFilter in self.filters):
                    self.callback(dt, packet.data)
        except SkipProcessStepException:
            self.logger.debug("skip processing step")


class TcpPacketInfo():

    class TcpOptions:
        def __init__(self):
            self.data = dict()
        def __getitem__(self, key):
            return self.data[key]
        def __setitem__(self, key, val):
            self.data[key] = val


    def __init__(self, packet, module=None):
        self.tcp = packet.data

        if type(self.tcp) != TCP:
            raise InternalException("Only TCP packets are allowed")

        if module != None and not isinstance(module, Mod):
            raise InternalException(
                    "Argument module must be a subclass of module (not %s)" %
                    (type(module)))

        if type(packet) == dpkt.ip.IP:
            self.sip = Converter.dpkt_addr_to_string(packet.src)
            self.dip = Converter.dpkt_addr_to_string(packet.dst)
            self.ipversion = "IP "
        elif type(packet) == dpkt.ip6.IP6:
            self.sip = socket.inet_ntop(socket.AF_INET6, packet.src)
            self.dip = socket.inet_ntop(socket.AF_INET6, packet.dst)
            self.ipversion = "IP6"
        else:
            raise InternalException("unknown protocol")

        self.sport = int(self.tcp.sport)
        self.dport = int(self.tcp.dport)

        self.seq = int(self.tcp.seq)
        self.ack = int(self.tcp.ack)
        self.win = int(self.tcp.win)
        self.urp = int(self.tcp.urp)
        self.sum = int(self.tcp.sum)

        self.parse_tcp_options()

    def is_ack_flag(self):
        return self.tcp.flags & TH_ACK

    def is_syn_flag(self):
        return self.tcp.flags & TH_SYN

    def is_urg_flag(self):
        return self.tcp.flags & TH_URG

    def is_psh_flag(self):
        return self.tcp.flags & TH_PSH

    def is_fin_flag(self):
        return self.tcp.flags & TH_FIN

    def is_rst_flag(self):
        return self.tcp.flags & TH_RST

    def is_ece_flag(self):
        return self.tcp.flags & TH_ECE

    def is_cwr_flag(self):
        return self.tcp.flags & TH_CWR

    def linear_sackblocks_array(self, liste):
        retlist = list()
        i = len(liste) / 2
        while i > 0:
            r = list()
            r.append(liste.pop(-1))
            r.append(liste.pop(-1))
            retlist.append(r)
            i -= 1

        return retlist

    def parse_tcp_options(self):

        self.options = TcpPacketInfo.TcpOptions()
        self.options['mss'] = False
        self.options['wsc'] = False
        self.options['tsval'] = False
        self.options['tsecr'] = False
        self.options['sackok'] = False
        self.options['sackblocks'] = False

        opts = []
        for opt in dpkt.tcp.parse_opts(self.tcp.opts):
            try:
                o, d = opt
                if len(d) > 32: raise TypeError
            except TypeError:
                break
            if o == dpkt.tcp.TCP_OPT_MSS:
                self.options['mss'] = struct.unpack('>H', d)[0]
            elif o == dpkt.tcp.TCP_OPT_WSCALE:
                self.options['wsc'] = ord(d)
            elif o == dpkt.tcp.TCP_OPT_SACKOK:
                self.options['sackok'] = True
            elif o == dpkt.tcp.TCP_OPT_SACK:
                ofmt="!%sI" % int(len(d) / 4)
                self.options['sackblocks'] = self.linear_sackblocks_array(list(struct.unpack(ofmt, d)))
            elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                (self.options['tsval'], self.options['tsecr']) = struct.unpack('>II', d)

            opts.append(o)




class TcpConn:

    def __init__(self, packet):
        ip = packet
        tcp = packet.data

        self.ipversion = str(type(ip))
        self.sip       = Converter.dpkt_addr_to_string(ip.src)
        self.dip       = Converter.dpkt_addr_to_string(ip.dst)
        self.sport     = str(int(tcp.sport))
        self.dport     = str(int(tcp.dport))

        self.sipnum = ip.src
        self.dipnum = ip.dst

        l = [ord(a) ^ ord(b) for a,b in zip(self.sipnum, self.dipnum)]

        self.uid = "%s:%s:%s" % (
                str(self.ipversion),
                str(l),
                str(long(self.sport) + long(self.dport)))

        self.iuid = ((self.sipnum) + \
                (self.dipnum) + ((self.sport) + \
                (self.dport)))


    def __hash__(self):
        return self.iuid

    def __repr__(self):
        return "%s:%s<->%s:%s" % ( self.sip, self.sport,
                    self.dip, self.dport)


class SubConnectionStatistic:

    def __init__(self):
        self.packets_processed          = 0
        self.bytes_sent_link_layer      = 0
        self.bytes_sent_network_layer   = 0
        self.bytes_sent_transport_layer = 0
        self.bytes_sent_application_layer = 0


class SubConnection(TcpConn):

    def __init__(self, connection, packet):
        TcpConn.__init__(self, packet)
        self.connection = connection
        self.statistic = SubConnectionStatistic()
        self.user_data = dict()


    def __cmp__(self, other):
        if other == None:
            return True

        if (self.dipnum == other.dipnum and
            self.sipnum == other.sipnum and
            self.dport  == other.dport and
            self.sport  == other.sport and
            self.ipversion == other.ipversion):
                return False
        else:
            return True


    def __repr__(self):
        return "%s:%s -> %s:%s" % (
                    self.sip,
                    self.sport,
                    self.dip,
                    self.dport)


    def update(self, ts, packet):
        self.statistic.packets_processed += 1


    def set_subconnection_id(self, sub_connection_id):
        self.sub_connection_id = sub_connection_id



class ConnectionStatistic:

    def __init__(self):
        self.packets_processed          = 0
        self.bytes_sent_link_layer      = 0
        self.bytes_sent_network_layer   = 0
        self.bytes_sent_transport_layer = 0
        self.bytes_sent_application_layer = 0



class Connection(TcpConn):

    static_connection_id = 1

    def __init__(self, packet):
        TcpConn.__init__(self, packet)
        (self.sc1, self.sc2) = (None, None)
        self.connection_id = Connection.static_connection_id
        Connection.static_connection_id += 1
        self.statistic = ConnectionStatistic()

        self.capture_time_start = None
        self.capture_time_end = None

        # module users could use this container
        # to stick data to a connection
        self.user_data = dict()


    def __del__(self):
        Connection.static_connection_id -= 1


    def __cmp__(self, other):
        if self.ipversion != other.ipversion:
            return False
        if (self.dipnum == other.dipnum and
            self.sipnum == other.sipnum and
            self.dport  == other.dport and
            self.sport  == other.sport):
                return True
        elif (self.dipnum == other.sipnum and
             self.sipnum  == other.dipnum and
             self.dport   == other.sport and
             self.sport   == other.dport):
                return True
        else:
            return False

    def register_container(self, container):
        self.container = container


    def update_statistic(self, packet):
        self.statistic.packets_processed  += 1


    def update(self, ts, packet):
        self.update_statistic(packet)

        sc = SubConnection(self, packet)

        if self.capture_time_start == None:
            self.capture_time_start = ts

        self.capture_time_end = ts

        if self.sc1 == None:
            self.sc1 = sc
            self.sc1.update(ts, packet)
            self.sc1.set_subconnection_id(1)
            return

        if self.sc1 == sc:
            self.sc1.update(ts, packet)
            return

        if self.sc2 == sc:
            self.sc2.update(ts, packet)
            return

        self.sc2 = sc
        sc.update(ts, packet)
        sc.set_subconnection_id(2)


    def get_subconnection(self, packet):
        # we know that packet is a TCP packet
        if self.sc1 == None:
            raise InternalException("a connection without a subconnection?!")

        if str(self.sc1.sport) == str(packet.data.sport):
            return self.sc1
        else:
            assert(self.sc2)
            return self.sc2



class ConnectionContainerStatistic:

    def __init__(self):
        self.packets_processed = 0

        self.packets_nl_arp  = 0
        self.packets_nl_ipv4 = 0
        self.packets_nl_ipv6 = 0
        self.packets_nl_unknown = 0

        self.packets_tl_tcp  = 0
        self.packets_tl_udp  = 0
        self.packets_tl_icmp  = 0
        self.packets_tl_icmp6  = 0
        self.packets_tl_unknown  = 0

        # byte accounting
        self.bytes_sent_link_layer        = 0
        self.bytes_sent_network_layer     = 0
        self.bytes_sent_transport_layer   = 0



class ConnectionContainer:


    def __init__(self):
        self.container = dict()
        self.statistic = ConnectionContainerStatistic()
        self.capture_time_start = None
        self.capture_time_end = None


    def __len__(self):
        return len(self.container)


    def tcp_check(self, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return False

        if type(packet.data) != dpkt.tcp.TCP:
            return False

        return True


    def sub_connection_by_packet(self, packet):
        if not self.tcp_check(packet):
            return None

        c = Connection(packet)

        if not c.uid in self.container.keys():
            # this method SHOULD not be called if not
            # sure that the packet is already in the
            # container
            raise InternalException("packet MUST be in preprocesses container")

        return self.container[c.uid].get_subconnection(packet)


    def update(self, ts, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return

        if type(packet.data) != dpkt.tcp.TCP:
            return

        if self.capture_time_start == None:
            self.capture_time_start = ts

        self.capture_time_end = ts

        c = Connection(packet)

        # this is the only place where a connetion
        # is put into this container
        if not c.uid in self.container.keys():
            c.update(ts, packet)
            self.container[c.uid] = c
            c.register_container(self)
        else:
            cc = self.container[c.uid]
            cc.update(ts, packet)



class StatisticMod():

    LABEL_DB_INDEX_DESCRIPTION = 0
    LABEL_DB_INDEX_UNIT        = 1
    LABEL_DB_INDEX_INIT_VALUE  = 2

    LABEL_DB = {
        "packets-packets":        [ "Packets",        "packets", 0],

        "link-layer-byte":        [ "Data link layer",        "bytes  ", 0],
        "network-layer-byte":     [ "Data network layer",     "bytes  ", 0],
        "transport-layer-byte":   [ "Data transport layer",   "bytes  ", 0],
        "application-layer-byte": [ "Data application layer", "bytes  ", 0],

        "duration-timedelta": [ "Duration", "seconds ", 0.0],

        "link-layer-throughput-bitsecond":        [ "Link layer throughput",        "bit/s  ", 0.0],
        "network-layer-throughput-bitsecond":     [ "Network layer throughput",     "bit/s  ", 0.0],
        "transport-layer-throughput-bitsecond":   [ "Transport layer throughput",   "bit/s  ", 0.0],
        "application-layer-throughput-bitsecond": [ "Application layer throughput", "bit/s  ", 0.0],

        "rexmt-data-bytes":      [ "Retransmissions",            "bytes  ",   0],
        "rexmt-data-packets":    [ "Retransmissions",            "packets",   0],
        "rexmt-bytes-percent":   [ "Retransmissions per byte",   "percent", 0.0],
        "rexmt-packets-percent": [ "Retransmissions per packet", "percent", 0.0],

        "pure-ack-packets": [ "ACK flag set but no payload", "packets", 0],

        "push-flag-set-packets": [ "PUSH flag set",          "packets", 0],
        "ece-flag-set-packets":  [ "TCP-ECE (ECN) flag set", "packets", 0],
        "cwr-flag-set-packets":  [ "TCP-CWR (ECN) flag set", "packets", 0],

        "tl-ps-min":    [ "TCP Payload Size (min)",    "bytes", 0],
        "tl-ps-max":    [ "TCP Payload Size (max)",    "bytes", 0],
        "tl-ps-median": [ "TCP Payload Size (median)", "bytes", 0],
        "tl-ps-avg":    [ "TCP Payload Size (avg)",    "bytes", 0],
        "tl-ps-std":    [ "TCP Payload Size (stddev)", "bytes", 0],

        "tl-iats-min": [ "TCP packet inter-arrival times (min)", "microseconds", 0],
        "tl-iats-max": [ "TCP packet inter-arrival times (max)", "microseconds", 0],
        "tl-iats-avg": [ "TCP packet inter-arrival times (avg)", "microseconds", 0],
        "tl-iats-std": [ "TCP packet inter-arrival times (stddev)", "microseconds", 0],
    }
    
    def __init__(self, pcap_file_path, loglevel = None):
        self.pcap_file_path = pcap_file_path
        self.cc = ConnectionContainer()
        self.logger = logging.getLogger()
        self.loglevel = loglevel
         
        self.set_opts_logevel()

    def internal_pre_process_packet(self, ts, packet):
        """ this is a hidden preprocessing function, called for every packet"""
        self.cc.update(ts, packet)
        self.pre_process_packet(ts, packet)


    def check_new_subconnection(self, sc):
        if len(sc.user_data): return

        # initialize the data values in a loop, e.g
        #   sc.user_data["link-layer-byte"] = 0
        #   [...]
        index = StatisticMod.LABEL_DB_INDEX_INIT_VALUE
        for key in self.LABEL_DB:
            sc.user_data[key] = self.LABEL_DB[key][index]

        # helper variables comes here, helper
        # variables are marked with a leading
        # underscore.
        sc.user_data["_highest_data_seen"] = None
        sc.user_data["_tl_pkt_sizes"] = list()
        sc.user_data["_tl_iats"] = list()
        sc.user_data["_tl_ia_last"] = None

        sc.user_data["_flow_time_start"] = None
        sc.user_data["_flow_time_end"]   = None


    def type_to_label(self, label):
        return self.LABEL_DB[label][StatisticMod.LABEL_DB_INDEX_DESCRIPTION]

    def account_general_data(self, packet):
        if type(packet) == dpkt.ip.IP:
            self.cc.statistic.packets_nl_ipv4 += 1
        elif type(packet) == dpkt.ip6.IP6:
            self.cc.statistic.packets_nl_ipv6 += 1
        elif type(packet) == dpkt.arp.ARP:
            self.cc.statistic.packets_nl_arp += 1
            raise PacketNotSupportedException()
        else:
            self.cc.statistic.packets_nl_unknown += 1
            raise PacketNotSupportedException()

        if type(packet.data) == dpkt.tcp.TCP:
            self.cc.statistic.packets_tl_tcp += 1
        elif type(packet.data) == dpkt.udp.UDP:
            self.cc.statistic.packets_tl_udp += 1
            raise PacketNotSupportedException()
        elif type(packet.data) == dpkt.icmp.ICMP:
            self.cc.statistic.packets_tl_icmp += 1
            raise PacketNotSupportedException()
        elif type(packet.data) == dpkt.icmp6.ICMP6:
            self.cc.statistic.packets_tl_icmp6 += 1
            raise PacketNotSupportedException()
        else:
            self.cc.statistic.packets_tl_unknown += 1
            raise PacketNotSupportedException()


    def account_general_tcp_data(self, sc, ts, packet):
        sc.user_data["packets-packets"] += 1

        sc.user_data["link-layer-byte"]        += len(packet) + Info.ETHERNET_HEADER_LEN
        sc.user_data["network-layer-byte"]     += int(len(packet))
        sc.user_data["transport-layer-byte"]   += int(len(packet.data))
        sc.user_data["application-layer-byte"] += int(len(packet.data.data))

        # capture start and end on a per flow basis
        # This will be used for flow duration and flow throughput
        if not sc.user_data["_flow_time_start"]:
            sc.user_data["_flow_time_start"] = ts
        sc.user_data["_flow_time_end"] = ts

        self.cc.statistic.packets_processed += 1


    def rexmt_final(self, sc):
        # called at the end of traxing to check values
        # or do some final calculations, based on intermediate
        # values
        res = U.percent(sc.user_data["rexmt-data-bytes"], sc.user_data["application-layer-byte"])
        sc.user_data["rexmt-bytes-percent"] = res

        res = U.percent(sc.user_data["rexmt-data-packets"], sc.user_data["packets-packets"])
        sc.user_data["rexmt-packets-percent"] = res

        if len(sc.user_data["_tl_pkt_sizes"]) > 0:
            sc.user_data["tl-ps-min"]    = min(sc.user_data["_tl_pkt_sizes"])
            sc.user_data["tl-ps-max"]    = max(sc.user_data["_tl_pkt_sizes"])
            sc.user_data["tl-ps-avg"]    = numpy.mean(sc.user_data["_tl_pkt_sizes"])
            sc.user_data["tl-ps-median"] = numpy.median(sc.user_data["_tl_pkt_sizes"])
            sc.user_data["tl-ps-std"]    = numpy.std(sc.user_data["_tl_pkt_sizes"])

        if len(sc.user_data["_tl_iats"]) > 0:
            sc.user_data["tl-iats-min"] = min(sc.user_data["_tl_iats"])
            sc.user_data["tl-iats-max"] = max(sc.user_data["_tl_iats"])
            sc.user_data["tl-iats-avg"] = numpy.mean(sc.user_data["_tl_iats"])
            sc.user_data["tl-iats-std"] = numpy.std(sc.user_data["_tl_iats"])

        if sc.user_data["_flow_time_start"] != sc.user_data["_flow_time_end"]:
            sc.user_data["duration-timedelta"] = sc.user_data["_flow_time_end"] - sc.user_data["_flow_time_start"]
            sc.user_data["duration-timedelta"] =  U.ts_tofloat(sc.user_data["duration-timedelta"])

        if sc.user_data["duration-timedelta"] > 0.0:
            sc.user_data["link-layer-throughput-bitsecond"]        = ((sc.user_data["link-layer-byte"] * 8) / sc.user_data["duration-timedelta"])
            sc.user_data["network-layer-throughput-bitsecond"]     = ((sc.user_data["network-layer-byte"] * 8) / sc.user_data["duration-timedelta"])
            sc.user_data["transport-layer-throughput-bitsecond"]   = ((sc.user_data["transport-layer-byte"] * 8) / sc.user_data["duration-timedelta"])
            sc.user_data["application-layer-throughput-bitsecond"] = ((sc.user_data["application-layer-byte"] * 8) / sc.user_data["duration-timedelta"])
            # must be last operation!
            # we convert duration-timedelta to string with floating point
            # precision of .2
            sc.user_data["duration-timedelta"] = sc.user_data["duration-timedelta"]


    def account_rexmt(self, sc, packet, pi, ts):
        data_len = int(len(packet.data.data))
        transport_len = int(len(packet.data))

        actual_data = pi.seq + data_len
 
        if not sc.user_data["_highest_data_seen"]:
            # no rexmt possible, skip rexmt processing
            sc.user_data["_highest_data_seen"] = actual_data
            return

        if actual_data > sc.user_data["_highest_data_seen"]:
            # packet sequence number is highest sequence
            # number seen so far, no rexmt therefore
            sc.user_data["_highest_data_seen"] = actual_data
            if data_len > 0:
                sc.user_data["_tl_pkt_sizes"].append(transport_len)
                if sc.user_data["_tl_ia_last"] is not None:
                    delta = ts - sc.user_data["_tl_ia_last"]
                    sc.user_data["_tl_iats"].append((delta.seconds*1000000 + delta.microseconds))
                sc.user_data["_tl_ia_last"] = ts
            return

        if data_len == 0:
            # no data packet, cannot be a retransmission
            return

        # ok, rexmt happened
        sc.user_data["rexmt-data-packets"] += 1

        # now account rexmt bytes, we add one to take care
        sc.user_data["rexmt-data-bytes"] += data_len


    def account_pure_ack(self, sc, packet, pi):
        if pi.is_ack_flag() and int(len(packet.data.data)) == 0:
            sc.user_data["pure-ack-packets"] += 1


    def account_evil_bits(self, sc, packet, pi):
        if pi.is_psh_flag():
                sc.user_data["push-flag-set-packets"] += 1
        if pi.is_ece_flag():
                sc.user_data["ece-flag-set-packets"] += 1
        if pi.is_cwr_flag():
                sc.user_data["cwr-flag-set-packets"] += 1


    def account_tcp_data(self, sc, ts, packet, pi):
        self.account_rexmt(sc, packet, pi, ts)
        self.account_evil_bits(sc, packet, pi)
        self.account_pure_ack(sc, packet, pi)


    def pre_process_packet(self, ts, packet):
        try:
            self.account_general_data(packet)
        except PacketNotSupportedException:
            return

        sc = self.cc.sub_connection_by_packet(packet)
        if not sc: return InternalException()

        # make sure the data structure is initialized
        self.check_new_subconnection(sc)

        self.account_general_tcp_data(sc, ts, packet)

        # .oO guaranteed TCP packet now
        pi = TcpPacketInfo(packet)
        self.account_tcp_data(sc, ts, packet, pi)


    def print_sc_statistics(self, cid, statistic):
        for i in STATISTIC_LABELS:
            lbl = self.type_to_label(i) + ":"
            r = [str(sc.user_data[i]) + " " + self.LABEL_DB[i][1] for sc in statistic]

            for s in r:
                sys.stdout.write("   %s %s" % (lbl, s))

            sys.stdout.write("\n")

    def format_human(self):
        one_percent = float(self.cc.statistic.packets_processed) / 100

        prct_nl_arp     = float(self.cc.statistic.packets_nl_arp) / one_percent
        prct_nl_ip      = float(self.cc.statistic.packets_nl_ipv4) / one_percent
        prct_nl_ipv6    = float(self.cc.statistic.packets_nl_ipv6) / one_percent
        prct_nl_unknown = float(self.cc.statistic.packets_nl_unknown) / one_percent

        prct_tl_tcp     = float(self.cc.statistic.packets_tl_tcp) / one_percent
        prct_tl_udp     = float(self.cc.statistic.packets_tl_udp) / one_percent
        prct_tl_icmp    = float(self.cc.statistic.packets_tl_icmp) / one_percent
        prct_tl_icmp6   = float(self.cc.statistic.packets_tl_icmp6) / one_percent
        prct_tl_unknown = float(self.cc.statistic.packets_tl_unknown) / one_percent


        sys.stdout.write("General:\n")

        sys.stdout.write("\tPackets processed: %5d (%7.2f%%)\n" %
                (self.cc.statistic.packets_processed, float(100)))

        sys.stdout.write("\tNetwork Layer\n")
        sys.stdout.write("\t   ARP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_arp, prct_nl_arp))
        sys.stdout.write("\t   IPv4:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_ipv4, prct_nl_ip))
        sys.stdout.write("\t   IPv6:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_ipv6, prct_nl_ipv6))
        sys.stdout.write("\t   Unknown:   %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_unknown, prct_nl_unknown))

        sys.stdout.write("\tTransport Layer\n")
        sys.stdout.write("\t   TCP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_tcp, prct_tl_tcp))
        sys.stdout.write("\t   UDP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_udp, prct_tl_udp))
        sys.stdout.write("\t   ICMP:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_icmp, prct_tl_icmp))
        sys.stdout.write("\t   ICMPv6:    %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_icmp6, prct_tl_icmp6))
        sys.stdout.write("\t   Unknown:   %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_unknown, prct_tl_unknown))

        sys.stdout.write("\nConnections:\n")

        # first we sort in an separate dict
        d = dict()
        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            d[connection.connection_id] = connection

        for key in sorted(d.keys()):
            connection = d[key]
            sys.stdout.write("\n")
            sys.stdout.write(" %d %s \n\n" % (connection.connection_id, connection))

            # statistic
            sys.stdout.write("   Packets processed: %d (%.1f%%)\n" %
                    (connection.statistic.packets_processed,
                        float(connection.statistic.packets_processed) /
                        float(self.cc.statistic.packets_processed) * 100.0))
            sys.stdout.write("   Duration: %.2f seconds\n" % (U.ts_tofloat(connection.capture_time_end - connection.capture_time_start)))

            sys.stdout.write("\n")

            if connection.sc1 and connection.sc2:
                sys.stdout.write("   Flow %s.1  %s" % (connection.connection_id, connection.sc1))

                sys.stdout.write("   Flow %s.2  %s" % (connection.connection_id, connection.sc2))

                self.print_sc_statistics(connection.connection_id,
                                         [connection.sc1, connection.sc2])
            elif connection.sc1:
                sys.stdout.write("   Flow %s.1  %s" %
                                 (connection.connection_id, connection.sc1))

                self.print_sc_statistics(connection.connection_id, [connection.sc1])
            else:
                raise InternalException("sc1 should be the only one here")

            sys.stdout.write("\n")


    def process_final_data(self):
        # first we sort in an separate dict
        d = dict()
        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            d[connection.connection_id] = connection

        for key in sorted(d.keys()):
            connection = d[key]
            if connection.sc1:
                self.rexmt_final(connection.sc1)
            if connection.sc2:
                self.rexmt_final(connection.sc2)


    def process_final(self):
        self.process_final_data()

    def set_opts_logevel(self):
        if not self.loglevel:
            """ this is legitim: no loglevel specified"""
            return

        if self.loglevel == "debug":
            self.logger.setLevel(logging.DEBUG)
        elif self.loglevel == "info":
            self.logger.setLevel(logging.INFO)
        elif self.loglevel == "warning":
            self.logger.setLevel(logging.WARNING)
        elif self.loglevel == "error":
            self.logger.setLevel(logging.ERROR)
        else:
            raise ArgumentException("loglevel \"%s\" not supported" % self.loglevel)

    def get_subconnections_stats(self):
        d = dict()
        scs = list()

        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            d[connection.connection_id] = connection

        for key in sorted(d.keys()):
            connection = d[key]
            scs.append(connection.sc1)
            if (connection.sc2):
                scs.append(connection.sc2)

        return scs 

class Captcp:

    def __init__(self, pcap_file_path):
        self.setup_logging()
        self.pcap_file_path = pcap_file_path
        self.statistic = None
        self.filters = []

    def add_filter(self, srcmac, dstmac):
        self.filters.append([srcmac, dstmac])

    def setup_logging(self):
        ch = logging.StreamHandler()

        formatter = logging.Formatter("# %(message)s")
        ch.setFormatter(formatter)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.WARNING)
        self.logger.addHandler(ch)


    def check_pcap_filepath_sanity(self):
        statinfo = os.stat(self.pcap_file_path)
        if statinfo.st_size == 0:
            self.logger.error("PCAP file contains no data: %s - exiting" %
                              (self.pcap_file_path))
            return False
        return True


    def run(self):
        self.statistic = StatisticMod(self.pcap_file_path)

        # there are other usages two (without pcap parsing)
        # We check here and if pcap_file_path is not true
        # then we assume a non-pcap module
        if self.pcap_file_path:
            if not self.check_pcap_filepath_sanity():
                return 1
            # parse the whole pcap file first
            pcap_parser = PcapParser(self.pcap_file_path, self.filters)
            pcap_parser.register_callback(self.statistic.internal_pre_process_packet)
            self.logger.debug("call pre_process_packet [1/4]")
            pcap_parser.run()
            del pcap_parser

        self.logger.debug("call pre_process_final [4/4]")
        ret = self.statistic.process_final()

        return ret

    def get_subconnections_stats(self):
        return self.statistic.get_subconnections_stats()


"""
USAGE:

captcp = Captcp("1.pcap")
captcp.add_filter(None, None)
captcp.run()
for i in captcp.get_subconnections_stats():
    print "%s %s -> %s %s" % (i.sip, i.sport, i.dip, i.dport)
    print i.user_data['packets-packets']
"""
