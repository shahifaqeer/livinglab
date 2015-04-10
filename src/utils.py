import binascii
import socket
import struct
import dpkt
import operator

def eth_ntoa(buffer):
    """Converts a binary representation of a MAC address to the usual colon-separated version"""
    mac_lst=[]
    for i in range(0, len(binascii.hexlify(buffer)), 2):
        mac_lst.append(binascii.hexlify(buffer)[i:i+2])
    mac = ':'.join(mac_lst)
    return mac



def eth_aton(buffer):
    """Converts a string representation of a MAC address to a the corresponding binary format"""
    sp = buffer.split(':')
    buffer = ''.join(sp)
    return binascii.unhexlify(buffer)



def is_ip_private(ip):
    """Use a standard ip like "192.43.21.1" """
    f = struct.unpack('!I',socket.inet_pton(socket.AF_INET,ip))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    ) 
    for net in private:
        if (f & net[1] == net[0]):
            return True
    return False


def select_ip_in_pcap(pcap_file_path):
    """Parses a pcap file, collects the list of IP addresses involved and sorts
    them according to the amount of data they exchange.

    Then prompts the user for one of these IPs, and returns the address"""
    
    ips_dictionary = {}

    with open(pcap_file_path, 'rb') as pcap_file:
        try:
            pc = dpkt.pcap.Reader(pcap_file)

            for (ts, pkt) in pc:
                try:
                    eth = dpkt.ethernet.Ethernet(pkt)

                    if (eth.type == 2048):
                        ip = eth.data
                      
                        if (ip.src not in ips_dictionary):
                            ips_dictionary[ip.src] = 0
                        if (ip.dst not in ips_dictionary):
                            ips_dictionary[ip.dst] = 0
                        
                        ips_dictionary[ip.src] = ips_dictionary[ip.src] + len(eth)
                        ips_dictionary[ip.dst] = ips_dictionary[ip.dst] + len(eth)
                except:
                    continue
        except dpkt.NeedData:
            print "PCAP FILE %s is empty!" % pcap_file_path
            return "10.0.0.1"

    sorted_ips = sorted(ips_dictionary.items(), key=operator.itemgetter(1), reverse=True)

    print "PCAP FILE: %s" % pcap_file_path
    print "IP addresses found:\n"
    counter = 0
    for i in sorted_ips:
        counter = counter + 1
        print "%s -> Bytes exchanged: %d" % (socket.inet_ntoa(i[0]), i[1])
        if (counter % 10 == 0):
            c = raw_input("Show other ip addresses? (y/n): ")
            if (c != 'y'):
                break

    ip_addr = None
    while(ip_addr is None):
        ip_addr = raw_input("Which IP address should we analyze?: ") 
        if (socket.inet_aton(ip_addr) not in ips_dictionary):
            print "I can't find %s, try again" % ip_addr
            ip_addr = None

    return ip_addr


