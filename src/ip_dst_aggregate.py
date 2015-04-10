
import dpkt
import socket
import sys
import traceback
import utils
from sklearn.cluster import KMeans
import pylab as P
import scipy.stats
import scipy
import numpy

"""Generates the counting plot of the number of unique IP addresses contacted
by a given source IP.

The memory is unbounded.
"""

class IPCumulativePlot():

    def __init__(self, pcap_file_path):
        self._pcap_file_path = pcap_file_path

        self._first_arrival = {}
        self._inter_arrivals = []
        self._last_packet_ts = None



    def _generate_data(self, ip_filter=None):
        # Ask the ip address to the user if not provided
        if (ip_filter is None):
            ip_filter = utils.select_ip_in_pcap(self._pcap_file_path)

        ip_filter = socket.inet_aton(ip_filter)

        with open(self._pcap_file_path, 'rb') as pcap_file:
            try:
                pc = dpkt.pcap.Reader(pcap_file)
                for (ts, pkt) in pc:
                    try:
                        eth = dpkt.ethernet.Ethernet(pkt)

                        if (eth.type == 2048):
                            ip = eth.data
                            
                            src_ip = ip.src
                            dst_ip = ip.dst

                            if (ip_filter is None or src_ip == ip_filter):
                                self._process_packet(src_ip, dst_ip, ts)
                            if (ip_filter is None or dst_ip == ip_filter):
                                self._process_packet(dst_ip, src_ip, ts)

                    except:
                        print "Exception detected"
                        print "-"*60
                        traceback.print_exc(file=sys.stdout)
                        print "-"*60
            except dpkt.NeedData:
                print "File %s seems to be empty" % self._pcap_file_path

        for ip in self._first_arrival:
            self._inter_arrivals.append(self._first_arrival[ip])

        self._inter_arrivals.append(self._last_packet_ts)

        self._inter_arrivals.sort() 



    def _process_packet(self, ref_ip, other_ip, ts):
        if (self._last_packet_ts is None or self._last_packet_ts < ts):
            self._last_packet_ts = ts

        is_destination_new = False

        if (other_ip not in self._first_arrival):
            self._first_arrival[other_ip] = ts
        else:
            if (self._first_arrival[other_ip] > ts):
                self._first_arrival[other_ip] = ts



    def plot_cumulative_arrivals(self, ip_filter = None, figure_name = None):
        if (figure_name is None):
            figure_name = self._pcap_file_path[:-5] + "_cumulative_arrivals.png"

        self._generate_data(ip_filter)

        # Normalize time stamps
        first_ts = self._inter_arrivals[0]
        time_intervals = []

        for i in range(1, len(self._inter_arrivals)):
           time_intervals.append(self._inter_arrivals[i] - first_ts)

        fig = P.figure()

        y = range(len(time_intervals))
        y[len(y)-1] = y[len(y)-1] - 1
        
        P.plot(time_intervals, y, '.-b')

        P.xlabel("Time (sec)")
        P.ylabel("Number of unique IPs")

        P.savefig(figure_name)
        P.close(fig)



if (__name__ == "__main__"):
    hist = IPCumulativePlot("PCAP/normal_pc_usage/1427463339.pcap")
    hist.plot_cumulative_arrivals("128.112.92.34")

    hist = IPCumulativePlot("PCAP/normal_pc_usage/1427723796.pcap")
    hist.plot_cumulative_arrivals("128.112.92.34")

    hist = IPCumulativePlot("PCAP/normal_pc_usage/1426794552.pcap")
    hist.plot_cumulative_arrivals("10.8.113.202")

    hist = IPCumulativePlot("PCAP/normal_pc_usage/1427418026.pcap")
    hist.plot_cumulative_arrivals("10.0.0.39")

    hist = IPCumulativePlot("PCAP/smartthings/1427771428.pcap")
    hist.plot_cumulative_arrivals("10.42.0.89")

    hist = IPCumulativePlot("PCAP/smartthings/1426869641.pcap")
    hist.plot_cumulative_arrivals("10.42.0.89")

    hist = IPCumulativePlot("PCAP/smartthings/1426884342.pcap")
    hist.plot_cumulative_arrivals("10.42.0.89")
     
    hist = IPCumulativePlot("PCAP/photoframe/1426796941.pcap")
    hist.plot_cumulative_arrivals("192.168.71.103")

    hist = IPCumulativePlot("PCAP/photoframe/1426798809.pcap")
    hist.plot_cumulative_arrivals("192.168.71.103")

    hist = IPCumulativePlot("PCAP/photoframe/1426800838.pcap")
    hist.plot_cumulative_arrivals("192.168.71.103")

    hist = IPCumulativePlot("PCAP/photoframe/1426805483.pcap")
    hist.plot_cumulative_arrivals("192.168.71.103")

    hist = IPCumulativePlot("PCAP/photoframe/1426860393.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/photoframe/1426862185.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/photoframe/1427820194.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/ubi/1427073791.pcap")
    hist.plot_cumulative_arrivals("10.0.0.7")

    hist = IPCumulativePlot("PCAP/ubi/1427074231.pcap")
    hist.plot_cumulative_arrivals("10.0.0.7")

    hist = IPCumulativePlot("PCAP/ubi/1427074595.pcap")
    hist.plot_cumulative_arrivals("10.0.0.7")

    hist = IPCumulativePlot("PCAP/ubi/1427074959.pcap")
    hist.plot_cumulative_arrivals("10.0.0.7")
    
    hist = IPCumulativePlot("PCAP/nest/1427071765.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/nest/1427072278.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/nest/1427072373.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/nest/1427072620.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")

    hist = IPCumulativePlot("PCAP/nest/1427072692.pcap")
    hist.plot_cumulative_arrivals("10.0.0.5")
   
    hist = IPCumulativePlot("PCAP/ipcam/1426613650.pcap")
    hist.plot_cumulative_arrivals("10.42.0.44")

    hist = IPCumulativePlot("PCAP/ipcam/1426620982.pcap")
    hist.plot_cumulative_arrivals("10.42.0.44")

    hist = IPCumulativePlot("PCAP/ipcam/1426621823.pcap")
    hist.plot_cumulative_arrivals("10.42.0.44")

    hist = IPCumulativePlot("PCAP/ipcam/1426623622.pcap")
    hist.plot_cumulative_arrivals("10.42.0.44")

    hist = IPCumulativePlot("PCAP/ipcam/1426628229.pcap")
    hist.plot_cumulative_arrivals("10.42.0.44")

    hist = IPCumulativePlot("PCAP/ipcam/1426780351.pcap")
    hist.plot_cumulative_arrivals("192.168.71.102")

