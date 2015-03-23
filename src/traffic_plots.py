#!/usr/bin/env python

import sys, getopt
import dpkt, binascii, socket
import struct
from pylab import *

def eth_ntoa(buffer):
    """Convert a binary representation of a MAC address to the usual colon-separated version"""
    mac_lst=[]
    for i in range(0, len(binascii.hexlify(buffer)), 2):
        mac_lst.append(binascii.hexlify(buffer)[i:i+2])
    mac = ':'.join(mac_lst)
    return mac

def isIpPrivate(ip):
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

def extractTrafficTimeSeries(inputFilePath, deviceMacAddr, timeResolution, outputFileName):
    pcap_file = open(inputFilePath)

    dpcap = dpkt.pcap.Reader(pcap_file)

    firstRun = True 

    ingress = []
    ingress_from_private_ip = []
    ingress_from_public_ip = []
    egress = []
    egress_to_private_ip = []
    egress_to_public_ip = []
    ingress_non_ip = []
    egress_non_ip = []

    ingress_ip_addresses_pub = []
    ingress_ip_addresses_priv = []
    ingress_ip_addresses = []
    egress_ip_addresses_pub = []
    egress_ip_addresses_priv = []
    egress_ip_addresses = []

    ingress_tcp_src_ports = [0] * 65535
    ingress_tcp_dst_ports = [0] * 65535
    egress_tcp_src_ports = [0] * 65535
    egress_tcp_dst_ports = [0] * 65535
    ingress_udp_src_ports = [0] * 65535
    ingress_udp_dst_ports = [0] * 65535
    egress_udp_src_ports = [0] * 65535
    egress_udp_dst_ports = [0] * 65535

    lastTime = 0
    
    for ts, buf in dpcap:
        if (firstRun):
            firstRun = False
            startTime = ts
       
        tsId = int((ts - startTime)/timeResolution)

        while (len(ingress)-1 < tsId):
            ingress.append(0)
            egress.append(0)
            ingress_non_ip.append(0)
            egress_non_ip.append(0)
            
            ingress_from_private_ip.append(0)
            ingress_from_public_ip.append(0)
            egress_to_private_ip.append(0)
            egress_to_public_ip.append(0)

            ingress_ip_addresses_pub.append({})
            egress_ip_addresses_pub.append({})
            ingress_ip_addresses_priv.append({})
            egress_ip_addresses_priv.append({})

            ingress_ip_addresses.append(0)
            egress_ip_addresses.append(0)

        lastTime = ts
        
        eth = dpkt.ethernet.Ethernet(buf)

        srcMac = eth_ntoa(eth.src)
        dstMac = eth_ntoa(eth.dst)

        if (deviceMacAddr == None or srcMac == deviceMacAddr):
            egress[tsId] = egress[tsId] + len(eth)
            if (type(eth.data) is dpkt.ip.IP):
                ip = eth.data

                dstIp = socket.inet_ntoa(ip.dst)

                if (isIpPrivate(dstIp)):
                    egress_to_private_ip[tsId] = egress_to_private_ip[tsId] + len(eth)
                    egress_ip_addresses_priv[tsId][dstIp] = 1
                else:
                    egress_to_public_ip[tsId] = egress_to_public_ip[tsId] + len(eth)
                    egress_ip_addresses_pub[tsId][dstIp] = 1
                
                if (ip.p == dpkt.ip.IP_PROTO_TCP):
                    srcPort = ip.data.sport - 1
                    dstPort = ip.data.dport - 1

                    egress_tcp_src_ports[srcPort] = egress_tcp_src_ports[srcPort] + len(eth)
                    egress_tcp_dst_ports[dstPort] = egress_tcp_dst_ports[dstPort] + len(eth)

                elif (ip.p == dpkt.ip.IP_PROTO_UDP):
                    srcPort = ip.data.sport - 1
                    dstPort = ip.data.dport - 1

                    egress_udp_src_ports[srcPort] = egress_udp_src_ports[srcPort] + len(eth)
                    egress_udp_dst_ports[dstPort] = egress_udp_dst_ports[dstPort] + len(eth)
            else:
                egress_non_ip[tsId] = egress_non_ip[tsId] + len(eth)

        if (deviceMacAddr == None or dstMac == deviceMacAddr):
            ingress[tsId] = ingress[tsId] + len(eth)
            if (type(eth.data) is dpkt.ip.IP):
                ip = eth.data

                srcIp = socket.inet_ntoa(ip.src)

                if (isIpPrivate(srcIp)):
                    ingress_from_private_ip[tsId] = ingress_from_private_ip[tsId] + len(eth)
                    ingress_ip_addresses_priv[tsId][srcIp] = 1
                else:
                    ingress_from_public_ip[tsId] = ingress_from_public_ip[tsId] + len(eth)
                    ingress_ip_addresses_pub[tsId][srcIp] = 1

                if (ip.p == dpkt.ip.IP_PROTO_TCP):
                    srcPort = ip.data.sport - 1
                    dstPort = ip.data.dport - 1

                    ingress_tcp_src_ports[srcPort] = ingress_tcp_src_ports[srcPort] + len(eth)
                    ingress_tcp_dst_ports[dstPort] = ingress_tcp_dst_ports[dstPort] + len(eth)

                elif (ip.p == dpkt.ip.IP_PROTO_UDP):
                    srcPort = ip.data.sport - 1
                    dstPort = ip.data.dport - 1

                    ingress_udp_src_ports[srcPort] = ingress_udp_src_ports[srcPort] + len(eth)
                    ingress_udp_dst_ports[dstPort] = ingress_udp_dst_ports[dstPort] + len(eth)
            else:
                ingress_non_ip[tsId] = ingress_non_ip[tsId] + len(eth)

    pcap_file.close()
    
    for i in range(len(ingress)):
        # Compute the traffic BW in kbytes/s
        ingress[i] = ingress[i] / ( 1024 * float(timeResolution) )
        egress[i] = egress[i] / ( 1024 * float(timeResolution) )

        ingress_from_public_ip[i] = ingress_from_public_ip[i] / ( 1024 * float(timeResolution) )
        ingress_from_private_ip[i] = ingress_from_private_ip[i] / ( 1024 * float(timeResolution) )
        egress_to_public_ip[i] = egress_to_public_ip[i] / ( 1024 * float(timeResolution) )
        egress_to_private_ip[i] = egress_to_private_ip[i] / ( 1024 * float(timeResolution) )

        # Count the unique IP Addresses
        ingress_ip_addresses_priv[i] = len(ingress_ip_addresses_priv[i])
        ingress_ip_addresses_pub[i] = len(ingress_ip_addresses_pub[i])
        egress_ip_addresses_priv[i] = len(egress_ip_addresses_priv[i])
        egress_ip_addresses_pub[i] = len(egress_ip_addresses_pub[i])
        ingress_ip_addresses[i] = ingress_ip_addresses_priv[i] + ingress_ip_addresses_pub[i]
        egress_ip_addresses[i] = egress_ip_addresses_priv[i] + egress_ip_addresses_pub[i]

    # Normalize transport-layer ports data

    for p in range(65535):
        ingress_tcp_src_ports[p] = ingress_tcp_src_ports[p] / float(1024)
        ingress_tcp_dst_ports[p] = ingress_tcp_dst_ports[p] / float(1024)
        egress_tcp_src_ports[p] = egress_tcp_src_ports[p] / float(1024)
        egress_tcp_dst_ports[p] = egress_tcp_dst_ports[p] / float(1024)
        ingress_udp_src_ports[p] = ingress_udp_src_ports[p] / float(1024)
        ingress_udp_dst_ports[p] = ingress_udp_dst_ports[p] / float(1024)
        egress_udp_src_ports[p] = egress_udp_src_ports[p] / float(1024)
        egress_udp_dst_ports[p] = egress_udp_dst_ports[p] / float(1024)

    # Generate traffic plots

    x = [range(len(ingress)), range(len(egress))]
    y = [ingress, egress]
    labels = ["Ingress Traffic", "Egress Traffic"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "kb/s", "%s_trafficPlot.png" % outputFileName)
    
    x = [range(len(ingress_from_public_ip)), range(len(ingress_from_private_ip))]
    y = [ingress_from_public_ip, ingress_from_private_ip]
    labels = ["Ingress Public IP", "Ingress Private IP"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "kb/s", "%s_ingressTraffic.png" % outputFileName)

    x = [range(len(egress_to_public_ip)), range(len(egress_to_private_ip))]
    y = [egress_to_public_ip, egress_to_private_ip]
    labels = ["Egress Public IP", "Egress Private IP"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "kb/s", "%s_egressTraffic.png" % outputFileName)

    x = [range(len(ingress_non_ip)), range(len(egress_non_ip))]
    y = [ingress_non_ip, egress_non_ip]
    labels = ["Ingress non IPv4", "Egress non IPv4"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "kb/s", "%s_non_ipv4_traffic.png" % outputFileName)

    # Generate number of IP Addresses plots

    x = [range(len(ingress_ip_addresses)), range(len(egress_ip_addresses))]
    y = [ingress_ip_addresses, egress_ip_addresses]
    labels = ["Ingress Unique IP Addr", "Egress Unique IP Addr"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "# IP Addr", "%s_uniqueIpAddr.png" % outputFileName)

    x = [range(len(egress_ip_addresses_pub)), range(len(egress_ip_addresses_priv))]
    y = [egress_ip_addresses_pub, egress_ip_addresses_priv]
    labels = ["Egress Public IP", "Egress Private IP"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "# IP Addr", "%s_egressIpAddr.png" % outputFileName)

    x = [range(len(ingress_ip_addresses_pub)), range(len(ingress_ip_addresses_priv))]
    y = [ingress_ip_addresses_pub, ingress_ip_addresses_priv]
    labels = ["Ingres Public IP", "Egress Private IP"]
    plotData(x, y, labels, "Time (%s seconds)" % timeResolution, "# IP Addr", "%s_ingressIpAddr.png" % outputFileName)

    # Generate TCP Ports plots
    
    x = [range(1,65536), range(1,65536)]
    y = [ingress_tcp_src_ports, egress_tcp_dst_ports]
    labels = ["Ingress TCP SRC ports", "Egress TCP DST ports"]
    plotData(x, y, labels, "TCP port number", "Data [kb]", "%s_tcpPorts.png" % outputFileName)

    x = [range(1,1025), range(1,1025)]
    y = [ingress_tcp_src_ports[0:1024], egress_tcp_dst_ports[0:1024]]
    labels = ["Ingress TCP SRC ports", "Egress TCP DST ports"]
    plotData(x, y, labels, "TCP port number", "Data [kb]", "%s_tcpPortsDetail.png" % outputFileName)

    x = [range(1,65536), range(1,65536)]
    y = [ingress_udp_src_ports, egress_udp_dst_ports]
    labels = ["Ingress UDP SRC ports", "Egress UDP DST ports"]
    plotData(x, y, labels, "UDP port number", "Data [kb]", "%s_udpPorts.png" % outputFileName)

    x = [range(1,65536), range(1, 65536)]
    y = [ingress_tcp_dst_ports, egress_tcp_src_ports]
    labels = ["Ingress TCP DST ports", "Egress TCP SRC ports"]
    plotData(x, y, labels, "TCP port number", "Data [kb]", "%s_tcpPortsReversed.png" % outputFileName)

    x = [range(1,1025), range(1,1025)]
    y = [ingress_tcp_dst_ports[0:1024], egress_tcp_src_ports[0:1024]]
    labels = ["Ingress TCP DST ports", "Egress TCP SRC ports"]
    plotData(x, y, labels, "TCP port number", "Data [kb]", "%s_tcpPortsDetailReversed.png" % outputFileName)

    x = [range(1,65536), range(1,65536)]
    y = [ingress_udp_dst_ports, egress_udp_src_ports]
    labels = ["Ingress UDP DST ports", "Egress UDP SRC ports"]
    plotData(x, y, labels, "UDP port number", "Data [kb]", "%s_udpPortsReversed.png" % outputFileName)

def plotData(x, y, dataLegendLabels, xAxisLabel, yAxisLabel, outFileName):
    lineStyles = ['.-r', 'x-b']

    figure()

    if (not isinstance(x, list)):
        x = [[x]]
        y = [[y]]
        dataLegendLabels = [[dataLegendLabels]]

    for i in range(len(x)):
        plot(range(len(x[i])), y[i], lineStyles[i % len(lineStyles)], label=dataLegendLabels[i])
    
    xlabel(xAxisLabel)
    ylabel(yAxisLabel)
    legend(loc="best", shadow=True)
    grid(True)
    savefig(outFileName)
    #show()

def parseInputParams(inputParameters):
    inputFilePath = "log.pcap"
    deviceMacAddr = None
    timeResolutionSeconds = 1
    outputFileName = "out"

    try:
        opts, args = getopt.getopt(inputParameters,"hi:o:m:t:",["inputFile=","outputFile=","deviceMacAddr=","timeRes="])
    except getopt.GetoptError:
        print "OPTIONS: -i <PCAP input file> -o <Output file name> -m <Device Mac address> -t <Time Resolution>"
        sys.exit(2)

    for opt,arg in opts:
        if opt == "-h":
            print "OPTIONS: -i <PCAP input file> -o <Output file name> -m <Device Mac address> -t <Time Resolution>"
            sys.exit()
        elif opt == "-i":
            inputFilePath = arg
        elif opt == "-o":
            outputFileName = arg
        elif opt == "-m":
            deviceMacAddr = arg
        elif opt == "-t":
            timeResolutionSeconds = float(arg)
    
    extractTrafficTimeSeries(inputFilePath, deviceMacAddr, timeResolutionSeconds, outputFileName)

if (__name__ == "__main__"):
    parseInputParams(sys.argv[1:])

