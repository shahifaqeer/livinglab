
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

"""Generates a histogram of the average number of new IP addessess
contacted by a given source IP within the sampling period.

The standard parameters are reported below:

    - Sampling seconds = 1 second
    - Memory seconds = None

If the memory parameter is set to None, the memory is restricted to the 
sampling interval: by moving to the next time interval, all the known IP 
addresses are deleted. 
"""

class IPHistogram():

    def __init__(self, pcap_file_path, sampling_seconds = 1, memory_seconds=None):
        self._pcap_file_path = pcap_file_path
        self._sampling_seconds = sampling_seconds
        self._memory_seconds = memory_seconds

        self._known_ips = {}
        self._new_ips = []
        self._pkts_received_in_ts = []

        self._first_ts = None
        self._begin_previous_ts = None
        


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



    def _clear_buffer(self, ts):
        if (self._begin_previous_ts is None):
            self._first_ts = ts
            self._begin_previous_ts = ts
            self._known_ips = {}
            self._new_ips = [0]
            self._pkts_received_in_ts = [0]
        elif (ts > self._begin_previous_ts + self._sampling_seconds):
            # If the memory is not set, expire the known IPs only if a new 
            # time slot is generated
            if (self._memory_seconds is None):
                self._known_ips = {}

            while (ts > self._begin_previous_ts + self._sampling_seconds):
                self._begin_previous_ts = self._begin_previous_ts + self._sampling_seconds
                self._new_ips.append(0)
                self._pkts_received_in_ts.append(0)

        # If the memory is set, expire the ips learnt far in the past
        if (self._memory_seconds is not None):
            ips_to_remove = []
            for ip in self._known_ips:
                if (ts - self._memory_seconds > self._known_ips[ip]):
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                self._known_ips.pop(ip, None)



    def _process_packet(self, ref_ip, other_ip, ts):
        is_destination_new = False

        if (other_ip not in self._known_ips):
            is_destination_new = True

        self._known_ips[other_ip] = ts

        ts_index = int((ts - self._first_ts) / float(self._sampling_seconds))
        self._pkts_received_in_ts[ts_index] = 1

        if (is_destination_new):
            self._new_ips[ts_index] = self._new_ips[ts_index] + 1



    def plot_histogram(self, ip_filter = None, figure_name = None):
        if (figure_name is None):
            if (self._memory_seconds is None):
                figure_name = self._pcap_file_path[:-5] + "_count_unique_ips_time" + str(self._sampling_seconds) + ".png"
            else:
                figure_name = self._pcap_file_path[:-5] + "_count_unique_ips_time" + str(self._sampling_seconds) + "_mem_" + str(self._memory_seconds) + ".png"

        self._generate_histogram_data(ip_filter)

        # Remove time slots in which no packets have been received
        for i in range(len(self._pkts_received_in_ts)):
            i = len(self._pkts_received_in_ts) - 1 - i
            if (self._pkts_received_in_ts[i] == 0):
                self._new_ips.pop(i)

        max_new_ips = 0

        for new_ips in self._new_ips:
            if (max_new_ips < new_ips):
                max_new_ips = new_ips

        fig = P.figure()

        number_of_new_ips = sum(self._new_ips)
        estimated_rate = (number_of_new_ips / float(len(self._new_ips)))
        
        # Negative binomial method of moments
        # When the mean is larger than variance do not use it
        sample_mean = float(scipy.mean(self._new_ips))
        sample_var = float(scipy.var(self._new_ips))
        if (sample_mean < sample_var):
            p_hat = sample_mean / sample_var
            n_hat = sample_mean * p_hat / (1 - p_hat)

        weights = numpy.ones_like(self._new_ips) / float(len(self._new_ips))

        n, bins, patches = P.hist(self._new_ips, max_new_ips, weights=weights)
        P.plot(range(max_new_ips+1), scipy.stats.poisson.pmf(range(max_new_ips+1), estimated_rate), '-r')
        if (sample_mean < sample_var):
            P.plot(range(max_new_ips+1), scipy.stats.nbinom.pmf(range(max_new_ips+1), n=n_hat, p=p_hat), '--g')
        P.title("MLE Estimate of the rate %f" % estimated_rate)
        P.xlabel("Number of new IPs")
        P.ylabel("Number of samples")

        P.savefig(figure_name)

        P.close(fig)



if (__name__ == "__main__"):

    for i in [1, 10, 60, 600]:
        for memory in [None, i*2, 10, 60, 600, 3600]:
            if (memory is not None and memory <= i):
                continue

            hist = IPHistogram("PCAP/normal_pc_usage/1427463339.pcap", i, memory)
            hist.plot_histogram("128.112.92.34")

            hist = IPHistogram("PCAP/normal_pc_usage/1427723796.pcap", i, memory)
            hist.plot_histogram("128.112.92.34")

            hist = IPHistogram("PCAP/normal_pc_usage/1426794552.pcap", i, memory)
            hist.plot_histogram("10.8.113.202")

            hist = IPHistogram("PCAP/normal_pc_usage/1427418026.pcap", i, memory)
            hist.plot_histogram("10.0.0.39")

            hist = IPHistogram("PCAP/smartthings/1427771428.pcap", i, memory)
            hist.plot_histogram("10.42.0.89")

            hist = IPHistogram("PCAP/smartthings/1426869641.pcap", i, memory)
            hist.plot_histogram("10.42.0.89")

            hist = IPHistogram("PCAP/smartthings/1426884342.pcap", i, memory)
            hist.plot_histogram("10.42.0.89")
             
            hist = IPHistogram("PCAP/photoframe/1426796941.pcap", i, memory)
            hist.plot_histogram("192.168.71.103")

            hist = IPHistogram("PCAP/photoframe/1426798809.pcap", i, memory)
            hist.plot_histogram("192.168.71.103")

            hist = IPHistogram("PCAP/photoframe/1426800838.pcap", i, memory)
            hist.plot_histogram("192.168.71.103")

            hist = IPHistogram("PCAP/photoframe/1426805483.pcap", i, memory)
            hist.plot_histogram("192.168.71.103")

            hist = IPHistogram("PCAP/photoframe/1426860393.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/photoframe/1426862185.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/photoframe/1427820194.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/ubi/1427073791.pcap", i, memory)
            hist.plot_histogram("10.0.0.7")

            hist = IPHistogram("PCAP/ubi/1427074231.pcap", i, memory)
            hist.plot_histogram("10.0.0.7")

            hist = IPHistogram("PCAP/ubi/1427074595.pcap", i, memory)
            hist.plot_histogram("10.0.0.7")

            hist = IPHistogram("PCAP/ubi/1427074959.pcap", i, memory)
            hist.plot_histogram("10.0.0.7")
            
            hist = IPHistogram("PCAP/nest/1427071765.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/nest/1427072278.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/nest/1427072373.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/nest/1427072620.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")

            hist = IPHistogram("PCAP/nest/1427072692.pcap", i, memory)
            hist.plot_histogram("10.0.0.5")
           
            hist = IPHistogram("PCAP/ipcam/1426613650.pcap", i, memory)
            hist.plot_histogram("10.42.0.44")

            hist = IPHistogram("PCAP/ipcam/1426620982.pcap", i, memory)
            hist.plot_histogram("10.42.0.44")

            hist = IPHistogram("PCAP/ipcam/1426621823.pcap", i, memory)
            hist.plot_histogram("10.42.0.44")

            hist = IPHistogram("PCAP/ipcam/1426623622.pcap", i, memory)
            hist.plot_histogram("10.42.0.44")

            hist = IPHistogram("PCAP/ipcam/1426628229.pcap", i, memory)
            hist.plot_histogram("10.42.0.44")

            hist = IPHistogram("PCAP/ipcam/1426780351.pcap", i, memory)
            hist.plot_histogram("192.168.71.102")


