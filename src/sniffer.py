import threading
import Queue
import logging
import socket
import pcap
import traceback
import dpkt
import gui.popup as popup

class SynchronizedFeatureExtractor():
    """This class implements a synchronous data structure to compute the number
    of unique IPs a given source IP address is talking to.
    
    For performance reasons it is implemented as a PriorityQueue, ordered by
    the time stamp of incoming packets.
    
    It process packets in time slots. When a time slot is completed, it is 
    possible to invoke the get_time_slot_feature method to extract a feature
    with the number of IPs contacted in the last time slots.
    """

    def __init__(self, memory_seconds, features_lag):
        self._memory_seconds = memory_seconds
        self._feature = [-1] * features_lag

        self._lock = threading.Lock()
        self._packet_queue = Queue.PriorityQueue()
        self._known_ips = {}
        self._last_time_slot_end_ts = None
        self._last_packet_received = None



    def add_packet(self, target_ip, time_stamp):
        """Adds a packet to the buffer. If the packet was received before the
        last time the get_time_slot_feature method was invoked, it will be
        dropped"""
        self._lock.acquire()

        if (self._last_time_slot_end_ts is None or
                time_stamp > self._last_time_slot_end_ts):
            self._packet_queue.put((time_stamp, target_ip))

        if (self._last_packet_received is None or
                self._last_packet_received < time_stamp):
            self._last_packet_received = time_stamp


        self._lock.release()



    def get_time_slot_feature(self, time_stamp):
        """Returns the feature for the given time slot and ends the current
        time slot."""
        self._lock.acquire()

        # Process all packets in the packet_queue, received before "time_stamp"
        while (self._packet_queue.qsize() > 0):
            (ts, ip) = self._packet_queue.get()

            if (ts > time_stamp):
                self._packet_queue.put((ts, ip))
                break

            # Update the dictionary of known IPS with the lastes ts of a
            # received packet
            if (ip not in self._known_ips or self._known_ips[ip] < ts):
                self._known_ips[ip] = ts

        num_known_ips = len(self._known_ips)

        # Discard old IPs according to the memory value
        memory_ts_limit = time_stamp - self._memory_seconds
        ips_to_purge = []

        for ip in self._known_ips:
            if (self._known_ips[ip] <= memory_ts_limit):
                ips_to_purge.append(ip)

        for ip in ips_to_purge:
            self._known_ips.pop(ip, None)

        self._last_time_slot_end_ts = time_stamp

        self._feature.append(num_known_ips)
        self._feature.pop(0)

        self._lock.release()

        return self._feature



    def get_last_packet_received_ts(self):
        self._lock.acquire()
        last_packet_ts = int(self._last_packet_received)
        self._lock.release()

        return last_packet_ts



class InterfaceSniffer(threading.Thread):
    """This class implements a thread to sniff a given network interface.
    
    It provides methods to operate in a thread-safe manner on the procedure 
    that is responsible to process the pcaps.
    """

    def __init__(self, interface, main_frame, memory_seconds, features_lag):
        threading.Thread.__init__(self)

        self._logger = logging.getLogger(__name__)

        self._interface = interface
        self._main_frame = main_frame
        self._memory_seconds = memory_seconds
        self._features_lag = features_lag

        # Objects used to synchronize the access to the shared variables
        self._lock = threading.Lock()
        self._event = threading.Event()

        self._is_thread_running = False
        self._should_thread_terminate = False

        # A dictionary that contains for each IP the time stamp of the last
        # packet received
        self._last_packet_ts = {}

        self._feature_extractors = {}
        self._trace_writers = {}

        self._last_ts_removed_old_ips = 0
        
        self._logger.debug("Initialized InterfaceSniffer on %s" % self._interface)



    def run(self):
        while(True):
            should_thread_terminate = False
            should_capture_packets = False

            self._event.wait(1)

            self._lock.acquire()
            if (self._should_thread_terminate):
                should_thread_terminate = True
            elif (self._is_thread_running):
                should_capture_packets = True
            self._lock.release()
            
            if (should_thread_terminate):
                break

            if (should_capture_packets):
                try:
                    self._capture_packets()
                except KeyboardInterrupt:
                    self._logger.debug("Sniffer for %s terminating main loop for KeyboardInterrupt" % self._interface)
                    self._logger.debug("Termination conditions for %s: should terminate %s should capture %s" % (self._interface, self._should_thread_terminate, self._is_thread_running))
                    break
                except:
                    exception_text = traceback.format_exc()
                    self._logger.error("Sniffer for %s terminating main loop for exception:\n%s" % (self._interface, exception_text))
                    popup.Dialog(self._main_frame, exception_text, ["Ok"])
            else:
                self._last_packet_ts = {}
                self._feature_extractors = {}
                self._close_trace_writers()

        self._logger.info("Sniffer for interface %s, gracefully ended" % self._interface)



    def _close_trace_writers(self):
        for ip in self._trace_writers:
            tw = self._trace_writers[ip]
            
            if (tw is not None):
                tw.close_file()
            
        self._trace_writers = {}
        
        
        
    def _capture_packets(self):
        try:
            self._logger.debug("Starting PCAP on interface %s" % self._interface)
            pc = pcap.pcap(self._interface)
            pc.setfilter("ip")
            pc.loop(self._capture_packet_loop)
        except KeyboardInterrupt:
            self.do_stop()
            raise
        except:
            self.do_stop()
            exception_text = traceback.format_exc()
            self._logger.error("Sniffer for %s in _capture_packets has detected the exception:\n%s" % (self._interface, exception_text))
            popup.Dialog(self._main_frame, exception_text, ["Ok"])
            raise



    def _capture_packet_loop(self, ts, pkt, d=None):
        try:
            should_thread_terminate = False
            should_capture_packets = False

            self._event.wait(1)

            self._lock.acquire()
            if (self._should_thread_terminate):
                should_thread_terminate = True
            elif (self._is_thread_running):
                should_capture_packets = True
            self._lock.release()

            if (should_thread_terminate or not should_capture_packets):
                # It is ugly but it seems to be a quick way for terminating
                # the pcap loop
                self._logger.debug("Sniffer throwing exception should_thread_terminate %s should_capture %s" % (should_thread_terminate, should_capture_packets))
                raise KeyboardInterrupt

            eth = dpkt.ethernet.Ethernet(pkt)

            if (eth.type == 2048):
                self._process_ip_packet(eth, ts)
        except KeyboardInterrupt:
            raise
        except:
            exception_text = traceback.format_exc()
            self._logger.error("Sniffer for %s in _capture_packets has detected the exception:\n%s" % (self._interface, exception_text))
            popup.Dialog(self._main_frame, exception_text, ["Ok"])



    def _process_ip_packet(self, eth, ts):
        ip = eth.data

        src_ip = ip.src
        dst_ip = ip.dst

        filters_src_ip = False
        filters_dst_ip = False

        self._lock.acquire()

        if (src_ip not in self._last_packet_ts or self._last_packet_ts[src_ip] < ts):
            self._last_packet_ts[src_ip] = ts
            if (src_ip not in self._feature_extractors):
                self._logger.debug("Sniffer %s detected the new IP %s" % (self._interface, socket.inet_ntoa(src_ip)))
                self._feature_extractors[src_ip] = None

        if (dst_ip not in self._last_packet_ts or self._last_packet_ts[dst_ip] < ts):
            self._last_packet_ts[dst_ip] = ts
            if (dst_ip not in self._feature_extractors):
                self._logger.debug("Sniffer %s detected the new IP %s" % (self._interface, socket.inet_ntoa(dst_ip)))
                self._feature_extractors[dst_ip] = None

        if (self._feature_extractors[src_ip] is not None):
            filters_src_ip = True

        if (self._feature_extractors[dst_ip] is not None):
            filters_dst_ip = True

        self._lock.release()

        if (filters_src_ip):
            self._feature_extractors[src_ip].add_packet(dst_ip, ts)

        if (filters_dst_ip):
            self._feature_extractors[dst_ip].add_packet(src_ip, ts)

        self._remove_old_ips(ts)



    def _remove_old_ips(self, ts):
        self._lock.acquire()
        ips_to_remove = []

        if (self._last_ts_removed_old_ips is None or self._last_ts_removed_old_ips < ts - self._memory_seconds):
            self._last_ts_removed_old_ips = ts

            for ip in self._last_packet_ts:
                last_packet = self._last_packet_ts[ip]

                if (last_packet < ts - self._memory_seconds * 2):
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                self._last_packet_ts.pop(ip, None)
                self._feature_extractors.pop(ip, None)

        self._lock.release()

        for ip in ips_to_remove:
            self._logger.info("Removed ip %s because didn't receive packets for long" % socket.inet_ntoa(ip))



    def add_ip_to_filter(self, ip, trace_writer = None):
        self._lock.acquire()
        if (ip in self._feature_extractors):
            self._feature_extractors[ip] = SynchronizedFeatureExtractor(self._memory_seconds, self._features_lag)
            self._trace_writers[ip] = trace_writer
        self._lock.release()

        self._logger.info("Sniffer for %s is now capturing %s" % (self._interface, socket.inet_ntoa(ip)))



    def remove_ip_to_filter(self, ip):
        self._lock.acquire()
        if (ip in self._trace_writers):
            self._trace_writers[ip].close_file()
            self._trace_writers[ip] = None
            self._feature_extractors[ip] = None
        self._lock.release()

        self._logger.info("Sniffer for %s is not capturing anymore %s" % (self._interface, socket.inet_ntoa(ip)))



    def do_start(self):
        self._lock.acquire()

        self._logger.info("Starting sniffer on interface %s" % self._interface)

        set_event = not self._is_thread_running
        self._is_thread_running = True

        # Generate a signal to quickly activate the thread which may be waiting
        if (set_event):
            self._event.set()

        self._lock.release()
        


    def do_stop(self):
        self._lock.acquire()

        self._logger.info("Stopped sniffer on interface %s" % self._interface)

        set_event = self._is_thread_running
        self._is_thread_running = False

        # Generate a signal to quickly activate the thread which may be waiting
        if (set_event):
            self._event.set()

        self._lock.release()



    def terminate(self):
        self._lock.acquire()

        self._logger.info("Terminating sniffer on interface %s" % self._interface)
        
        for ip in self._trace_writers:
            writer = self._trace_writers[ip]
            if (writer is not None):
                writer.close_file()
                
        self._trace_writers = {}

        self._should_thread_terminate = True
        self._event.set()

        self._lock.release()



    def get_sniffed_ips(self):
        self._lock.acquire()
        copy_list = list(self._feature_extractors)
        self._lock.release()

        return copy_list



    def get_samples_from_sniffed_ips(self, ts):
        self._lock.acquire()

        samples = []

        for ip in self._feature_extractors:
            sniffer = self._feature_extractors[ip]

            if (sniffer is not None):
                stats = sniffer.get_time_slot_feature(ts)
                samples.append([ip, stats])
                self._trace_writers[ip].append_feature(stats)

        self._lock.release()

        return samples

