
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

"""Generates a histogram of the interarrival times of new IP addresses 
contacted by a given source IP.

The standard parameter are reported below:

    - Memory seconds = None

If the memory parameter is set to None, the memory is unbounded.
"""

class IPInterarrivalHistogram():

    def __init__(self, pcap_file_path, memory_seconds=None):
        self._pcap_file_path = pcap_file_path
        self._memory_seconds = memory_seconds

        self._first_arrival = {}
        self._last_arrival = {}
        self._last_packet_ts = None
        self._inter_arrivals = []



    def _generate_histogram_data(self, ip_filter=None):
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

                            if (src_ip == ip_filter or dst_ip == ip_filter):
                                self._clear_buffer(ts)
                            
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

        self._inter_arrivals.sort() 



    def _clear_buffer(self, ts):
        if (self._memory_seconds is None):
            return
        
        ips_to_remove = []

        for ip in self._last_arrival:
            if (ts - self._last_arrival[ip] > self._memory_seconds):
                self._inter_arrivals.append(self._first_arrival[ip])
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            self._first_arrival.pop(ip, None)
            self._last_arrival.pop(ip, None)



    def _process_packet(self, ref_ip, other_ip, ts):
        if (self._last_packet_ts is None or self._last_packet_ts < ts):
            self._last_packet_ts = ts

        is_destination_new = False

        if (other_ip not in self._first_arrival):
            self._first_arrival[other_ip] = ts
            self._last_arrival[other_ip] = ts
        else:
            if (self._first_arrival[other_ip] > ts):
                self._first_arrival[other_ip] = ts

            if (self._last_arrival[other_ip] < ts):
                self._last_arrival[other_ip] = ts



    def plot_histogram(self, ip_filter = None, figure_name = None):
        if (figure_name is None):
            if (self._memory_seconds is None):
                figure_name = self._pcap_file_path[:-5] + "_interarrivals.png"
                log_figure_name = self._pcap_file_path[:-5] + "_log_interarrivals.png"
            else:
                figure_name = self._pcap_file_path[:-5] + "_interarrivals_mem_" + str(self._memory_seconds) + ".png"
                log_figure_name = self._pcap_file_path[:-5] + "_log_interarrivals_mem_" + str(self._memory_seconds) + ".png"

        self._generate_histogram_data(ip_filter)

        # Convert the timestamps into time intervals
        last_ts = self._inter_arrivals[0]
        time_intervals = []

        for i in range(1, len(self._inter_arrivals)):
           time_intervals.append(self._inter_arrivals[i] - last_ts)
           last_ts = self._inter_arrivals[i]

        fig = P.figure()

        estimated_rate = 1/float(scipy.mean(time_intervals))
        
        weights = numpy.ones_like(time_intervals) / float(len(time_intervals))
        
        cols = len(time_intervals)

        if (len(time_intervals) > 100):
            cols = 100
        
        if (len(time_intervals) > 0):
            n, bins, patches = P.hist(time_intervals, cols, weights=weights)
            P.plot(bins, scipy.stats.expon.pdf(bins, scale = 1 / estimated_rate), '-r')

            P.title("MLE Estimate of the rate %f" % estimated_rate)
            P.xlabel("Interarrival time")
            P.ylabel("Number of samples")

        P.savefig(figure_name)
        P.close(fig)

        # Compute the log-interarrivals

        for i in range(len(time_intervals)):
            time_intervals[i] = numpy.log(time_intervals[i])

        fig = P.figure()

        weights = numpy.ones_like(time_intervals) / float(len(time_intervals))
        n, bins, patches = P.hist(time_intervals, cols, weights=weights)

        P.xlabel("Log interarrival time")
        P.ylabel("Number of samples")
        P.savefig(log_figure_name)
        P.close(fig)



if (__name__ == "__main__"):

    for memory in [None, 1, 10, 60, 600, 3600]:
        hist = IPInterarrivalHistogram("PCAP/normal_pc_usage/1427463339.pcap", memory)
        hist.plot_histogram("128.112.92.34")

        hist = IPInterarrivalHistogram("PCAP/normal_pc_usage/1427723796.pcap", memory)
        hist.plot_histogram("128.112.92.34")

        hist = IPInterarrivalHistogram("PCAP/normal_pc_usage/1426794552.pcap", memory)
        hist.plot_histogram("10.8.113.202")

        hist = IPInterarrivalHistogram("PCAP/normal_pc_usage/1427418026.pcap", memory)
        hist.plot_histogram("10.0.0.39")

        hist = IPInterarrivalHistogram("PCAP/smartthings/1427771428.pcap", memory)
        hist.plot_histogram("10.42.0.89")

        hist = IPInterarrivalHistogram("PCAP/smartthings/1426869641.pcap", memory)
        hist.plot_histogram("10.42.0.89")

        hist = IPInterarrivalHistogram("PCAP/smartthings/1426884342.pcap", memory)
        hist.plot_histogram("10.42.0.89")
         
        hist = IPInterarrivalHistogram("PCAP/photoframe/1426796941.pcap", memory)
        hist.plot_histogram("192.168.71.103")

        hist = IPInterarrivalHistogram("PCAP/photoframe/1426798809.pcap", memory)
        hist.plot_histogram("192.168.71.103")

        hist = IPInterarrivalHistogram("PCAP/photoframe/1426800838.pcap", memory)
        hist.plot_histogram("192.168.71.103")

        hist = IPInterarrivalHistogram("PCAP/photoframe/1426805483.pcap", memory)
        hist.plot_histogram("192.168.71.103")

        hist = IPInterarrivalHistogram("PCAP/photoframe/1426860393.pcap", memory)
        hist.plot_histogram("10.0.0.5")

        hist = IPInterarrivalHistogram("PCAP/photoframe/1426862185.pcap", memory)
        hist.plot_histogram("10.0.0.5")
        
        hist = IPInterarrivalHistogram("PCAP/photoframe/1427820194.pcap", memory)
        hist.plot_histogram("10.0.0.5")

        hist = IPInterarrivalHistogram("PCAP/ubi/1427073791.pcap", memory)
        hist.plot_histogram("10.0.0.7")

        hist = IPInterarrivalHistogram("PCAP/ubi/1427074231.pcap", memory)
        hist.plot_histogram("10.0.0.7")

        hist = IPInterarrivalHistogram("PCAP/ubi/1427074595.pcap", memory)
        hist.plot_histogram("10.0.0.7")

        hist = IPInterarrivalHistogram("PCAP/ubi/1427074959.pcap", memory)
        hist.plot_histogram("10.0.0.7")
        
        hist = IPInterarrivalHistogram("PCAP/nest/1427071765.pcap", memory)
        hist.plot_histogram("10.0.0.5")

        hist = IPInterarrivalHistogram("PCAP/nest/1427072278.pcap", memory)
        hist.plot_histogram("10.0.0.5")

        hist = IPInterarrivalHistogram("PCAP/nest/1427072373.pcap", memory)
        hist.plot_histogram("10.0.0.5")
        
        hist = IPInterarrivalHistogram("PCAP/nest/1427072620.pcap", memory)
        hist.plot_histogram("10.0.0.5")

        hist = IPInterarrivalHistogram("PCAP/nest/1427072692.pcap", memory)
        hist.plot_histogram("10.0.0.5")
       
        hist = IPInterarrivalHistogram("PCAP/ipcam/1426613650.pcap", memory)
        hist.plot_histogram("10.42.0.44")

        hist = IPInterarrivalHistogram("PCAP/ipcam/1426620982.pcap", memory)
        hist.plot_histogram("10.42.0.44")

        hist = IPInterarrivalHistogram("PCAP/ipcam/1426621823.pcap", memory)
        hist.plot_histogram("10.42.0.44")

        hist = IPInterarrivalHistogram("PCAP/ipcam/1426623622.pcap", memory)
        hist.plot_histogram("10.42.0.44")

        hist = IPInterarrivalHistogram("PCAP/ipcam/1426628229.pcap", memory)
        hist.plot_histogram("10.42.0.44")

        hist = IPInterarrivalHistogram("PCAP/ipcam/1426780351.pcap", memory)
        hist.plot_histogram("192.168.71.102")


