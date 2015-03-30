#!/usr/bin/env python

import dpkt
import pylab
import utils
import os
import operator

"""
This file generates a time-series plot of the aggregate ingress/egress
traffic for a given mac address. 
"""
def generate_traffic_plots(path):
    """Utility function: it scans all the subfolder in path and generates
    all the plots for the available pcaps"""
    for root, subdirs, files in os.walk(path):
        for f in files:
            if (f[-5:] == ".pcap"):
                tp = TrafficParser(os.path.join(root, f))
                tp.generate_plots()

class TrafficParser():

    PLOT_SUFFIX_NAME = "_trts.png" 

    def __init__(self, pcap_file_path, mac_address = None):
        """When the src_mac_address is set to None, all the mac addresses will 
        be parsed"""
        self.pcap_file_path = pcap_file_path
        self.mac_address = mac_address

        self.mac_address_binary = utils.eth_aton(mac_address) if (mac_address is not None) else None
        self.parsed_data = self.get_pcap_traffic_series()

    def get_pcap_traffic_series(self):
        """Returns a time series for the traffic for all the mac addresses."""
        parsed_pcap_data = {}

        if (self.mac_address_binary is not None):
            parsed_pcap_data[self.mac_address_binary] = []

        with open(self.pcap_file_path, 'rb') as pcap_file:
            try:
                pcap = dpkt.pcap.Reader(pcap_file)
                for ts, buf in pcap:
                    # Skip non ethernet frames
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except:
                        continue

                    # Skip non-IP packets
                    if eth.type != 2048:
                        continue
                    
                    # Apply eth filter
                    if (self.mac_address_binary is not None):
                        self.append_data(parsed_pcap_data, self.mac_address_binary, eth, ts)
                    else:
                        if (eth.src not in parsed_pcap_data):
                            parsed_pcap_data[eth.src] = []
                        if (eth.dst not in parsed_pcap_data):
                            parsed_pcap_data[eth.dst] = []

                        self.append_data(parsed_pcap_data, eth.src, eth, ts)
                        self.append_data(parsed_pcap_data, eth.dst, eth, ts)
            except:
                print "Error parsing file: %s" % pcap_file
        
        # Remove mac addresses that didn't send data
        receivers_only = []
        for mac_addr in parsed_pcap_data:
            data_sent = False
            for data in parsed_pcap_data[mac_addr]:
                if (data[1] > 0):
                    data_sent = True
                    break
            if (not data_sent):
                receivers_only.append(mac_addr)

        for mac_addr in receivers_only:
            parsed_pcap_data.pop(mac_addr, None)

        # Sort the data 
        for mac_addr in parsed_pcap_data:
            series = sorted(parsed_pcap_data[mac_addr], key=operator.itemgetter(0))
            parsed_pcap_data[mac_addr] = series

        return parsed_pcap_data
    
    def append_data(self, parsed_pcap_data, expected_mac_addr, eth, ts):
        if (eth.src == expected_mac_addr):
            data = len(eth)
        elif (eth.dst == expected_mac_addr):
            data = -len(eth)
        else:
            return 
        
        parsed_pcap_data[expected_mac_addr].append((ts, data))

    def generate_plots(self):
        for mac_address in self.parsed_data:
            mac_address_str = utils.eth_ntoa(mac_address)
            plot_name = self.pcap_file_path[:-5] + "_" + mac_address_str + TrafficParser.PLOT_SUFFIX_NAME

            fig = pylab.figure()

            x = []
            y_sent_cumulative = []
            y_received_cumulative = []
            y_cumulative = []
            first_data = True
            start_ts = None

            for data in self.parsed_data[mac_address]:
                if (start_ts is None):
                    start_ts = data[0]

                if (first_data):
                    first_data = False
                    sent, received, cumul = 0,0,0
                else:
                    sent = y_sent_cumulative[len(x) - 1]
                    received = y_received_cumulative[len(x) - 1]
                    cumul = y_cumulative[len(x) - 1]

                if (data[1] > 0):
                    sent = sent + data[1]
                else:
                    received = received + data[1]

                cumul = cumul + data[1]

                x.append(data[0] - start_ts)
                y_sent_cumulative.append(sent)
                y_received_cumulative.append(received)
                y_cumulative.append(cumul)

            pylab.plot(x, y_sent_cumulative, ".-", label="Sent Data")
            pylab.plot(x, y_received_cumulative, ".-", label="Received Data")
            pylab.plot(x, y_cumulative, ".-", label="Cumulative")

            pylab.title("Traffic plot: %s" % mac_address_str)
            pylab.xlabel("Timestamp (s)")
            pylab.ylabel("Bytes Sent")
            pylab.grid(True)
            pylab.legend(loc="best", shadow=True)
            fig.savefig(plot_name)
            pylab.close(fig)

