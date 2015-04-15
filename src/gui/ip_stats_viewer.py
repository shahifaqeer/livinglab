import time
import urwid
import socket
import logging

class IPStatsViewer():
    """This class shows the statistics for each IP address. 
    """
    def __init__(self, main_frame, sampling_seconds, interface_selector, ip_selector, iot_classifier_dt, aggregate_stats_viewer):
        self._main_frame = main_frame
        self._sampling_seconds = sampling_seconds
        self._interface_selector = interface_selector
        self._ip_selector = ip_selector
        self._iot_classifier_dt = iot_classifier_dt
        self._aggregate_stats = aggregate_stats_viewer

        self._last_sampling_ts = time.time()

        self._list_walker = urwid.SimpleListWalker([])
        self._logger = logging.getLogger(__name__)



    def attach_to_loop(self, loop):
        """Makes sure that periodically the set of statistics for each IP
        is updated"""
        self._loop = loop
        self._sample_data()



    def _sample_data(self, loop=None, user_data=None):
        current_time = time.time()

        sampling_results = []
        traffic_sniffers = self._interface_selector.get_traffic_sniffers()

        # For accuracy reasons, buffer packets for 3 sampling seconds
        while (self._last_sampling_ts < current_time - 3 * self._sampling_seconds):
            new_sampling_ts = self._last_sampling_ts + self._sampling_seconds

            for interface in traffic_sniffers:
                sniffer = traffic_sniffers[interface]
                samples = sniffer.get_samples_from_sniffed_ips(new_sampling_ts)

                for s in samples:
                    ip = s[0]
                    feature = s[1]
                    num_ips = feature[-1]

                    is_iot_probability = self._iot_classifier_dt.iot_probability(feature)

                    sampling_results.append([interface, socket.inet_ntoa(ip), is_iot_probability, num_ips])

                    self._logger.debug("IP: %s is %f IOT - num_ips %d, %s" % (socket.inet_ntoa(ip), is_iot_probability, num_ips, str(feature)))

            self._last_sampling_ts = new_sampling_ts

        self._update_gui_with_samples(sampling_results)

        self._loop.set_alarm_in(self._sampling_seconds, self._sample_data)



    def _update_gui_with_samples(self, sampling_results):
        self._list_walker[:] = []

        collected_data = self._ip_selector.get_collected_data()

        for sample in sampling_results:
            interface = sample[0]
            iph = sample[1]
            ip = socket.inet_aton(iph)
            prob = sample[2] * 100
            num_ips = sample[3]

            expected_iot = collected_data[interface][ip][0]
            num_samples = collected_data[interface][ip][1] + 1
            
            self._aggregate_stats.add_sample(expected_iot)

            correct_samples = collected_data[interface][ip][2]

            if (prob >= 50 and expected_iot) or (prob < 50 and not expected_iot):
                correct_samples += 1
                self._aggregate_stats.add_correct_sample(expected_iot)

            collected_data[interface][ip][1] = num_samples
            collected_data[interface][ip][2] = correct_samples

            accuracy = 100 * correct_samples / float(num_samples)

            self._logger.debug("Interface %s ip %s expected_iot %s samples %d correct samples %d accuracy %f" % ( 
                interface, iph, expected_iot, num_samples, correct_samples, accuracy))

            ip_str = str(iph).ljust(16, ' ');
            prob_str = ("%d" % prob).ljust(3, ' ')
            iot_prob_str = (" Is IoT %s %%" % prob_str).ljust(14, ' ')
            accuracy_prob_str = ("%d" % accuracy).ljust(3, ' ')

            accuracy_str = (" Accuracy: %s %%" % accuracy_prob_str).ljust(16, ' ')
            text_label = "%s|%s|%s| Last # IPs %d" % (ip_str, iot_prob_str, accuracy_str, num_ips)

            self._list_walker.append(urwid.Text(text_label, "left"))

            self._logger.debug(text_label)



    def get_list_box(self):
        return urwid.ListBox(self._list_walker)
