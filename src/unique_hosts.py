#!/usr/bin/env python

import dpkt
import pylab
import utils
import os

"""
This file generates a time-series plot of the number of unique ip dst addresses
contacted by each device. Devices are identified by their source mac address.
"""
def generate_unique_dst_plots(path):
    """Utility function: it scans all the subfolder in path and generates
    all the plots for the available pcaps"""
    for root, subdirs, files in os.walk(path):
        for f in files:
            if (f[-5:] == ".pcap"):
                hp = UniqueDstHostsParser(os.path.join(root, f))
                hp.generate_plot()

class UniqueDstHostsParser():

    PLOT_SUFFIX_NAME = "_dst_hosts.png"

    def __init__(self, pcap_file_path, src_mac_address = None):
        """When the src_mac_address is set to None, all the Source mac
        addresses will be parsed"""
        self.pcap_file_path = pcap_file_path
        self.src_mac_address = src_mac_address
        self.ts_start = None
        self.ts_end = None
        self.ts_list = {}

        self.src_mac_address_binary = utils.eth_aton(src_mac_address) if (src_mac_address is not None) else None
        self.parsed_data = self.parse_pcap()

    def parse_pcap(self):
        parsed_pcap_data = self.get_pcap_target_hosts_series() 
        self.compute_src_mac_time_series(parsed_pcap_data)
        return parsed_pcap_data

    def get_pcap_target_hosts_series(self):
        """Returns the parsed_pcap_data that contains for each SRC MAC 
        address, a dictionary of the target IP addresses with the TS of
        the first packet sent to them.
        
        It also sets the ts_list, which contains for each SRC MAC
        the ordered list of time stamps for packets sent by it"""
        parsed_pcap_data = {}

        with open(self.pcap_file_path, 'rb') as pcap_file:
            try:
                pcap = dpkt.pcap.Reader(pcap_file)
                for ts, buf in pcap:
                    # Set the start ts
                    if (self.ts_start is None or self.ts_start > ts):
                        self.ts_start = ts
                        self.ts_end = ts

                    if (self.ts_end < ts):
                        self.ts_end = ts

                    # Skip non ethernet frames
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except:
                        continue
        
                    # Apply src eth filter
                    if (self.src_mac_address is None or eth.src == self.src_mac_address_binary):

                        # Skip non-IP packets
                        if eth.type != 2048:
                            continue
                        try:
                            # Read the ip destination
                            self.add_dst_ip(parsed_pcap_data, eth.data.dst, eth.src, ts)
                        except:
                            continue
            except:
                print "Error parsing file: %s" % pcap_file

        for src_mac in self.ts_list:
            self.ts_list[src_mac].sort()
        
        return parsed_pcap_data

    def add_dst_ip(self, parsed_pcap_data, dst_ip, src_mac, ts):
        if (src_mac in parsed_pcap_data):
            src_mac_data = parsed_pcap_data[src_mac]
            self.ts_list[src_mac].append(ts)

            if (dst_ip not in src_mac_data or src_mac_data[dst_ip] > ts):
                src_mac_data[dst_ip] = ts
        else:
            parsed_pcap_data[src_mac] = {dst_ip: ts}
            self.ts_list[src_mac] = [ts]

    def compute_src_mac_time_series(self, parsed_pcap_data):
        """Returns a data structure that conatins for each SRC MAC address,
        the sorted list of time stamps of the packets sent from the host"""
        for src_mac in parsed_pcap_data.keys():
            ip_dict = parsed_pcap_data[src_mac]
            ts_series = []
            for ip in ip_dict.keys():
                ts_series.append(ip_dict[ip] - self.ts_start)
            ts_series.sort()
            parsed_pcap_data[src_mac] = ts_series

    def generate_plot(self):
        plot_name = self.pcap_file_path[:-5] + UniqueDstHostsParser.PLOT_SUFFIX_NAME

        fig = pylab.figure()

        max_y = 0

        for src_mac in self.parsed_data.keys():
            x = self.ts_list[src_mac]
            increments = self.parsed_data[src_mac]
           
            num_of_ips = 0
            y = [0] * len(x)

            for i in range(len(x)):
                if (num_of_ips < len(increments) and x[i] >= increments[num_of_ips]):
                    num_of_ips = num_of_ips + 1
                y[i] = num_of_ips
                x[i] = x[i] - self.ts_start

            x.insert(0, 0)
            y.insert(0, 0)

            pylab.plot(x, y, ".-", label=utils.eth_ntoa(src_mac))

            new_max_y = y[len(y)-1]
            max_y = new_max_y if max_y < new_max_y else max_y

        pylab.xlabel("Timestamp (s)")
        pylab.ylabel("Number of unique DST IP")
        pylab.ylim([-0.5, max_y+1])
        pylab.grid(True)
        pylab.legend(loc="best", shadow=True)
        fig.savefig(plot_name)
        pylab.close(fig)
