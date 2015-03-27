import binascii
import socket

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

