import logging
import socket
import urwid
import threading
import gui.popup as popup
from trace_writer import TraceWriter

class IPSelector():
    """This class implements the behavior of the IP address selector.
    Periodically scans InterfaceSniffers of the InterfaceSelector and 
    if it detects a new IP address, it displays it to the available list.
    
    It also initializes the accuracy statistics.
    """
    def __init__(self, main_frame, sampling_seconds, memory_seconds, interface_selector):
        self._main_frame = main_frame
        self._sampling_seconds = sampling_seconds
        self._memory_seconds = memory_seconds
        self._interface_selector = interface_selector
        self._loop = None

        self._ip_addresses_walker = urwid.SimpleListWalker([])
        self._collected_data = {}
        self._lock = threading.Lock()

        self._logger = logging.getLogger(__name__)



    def attach_to_loop(self, loop):
        """Makes sure that every 5 seconds the list of known IP addresses is  
        updated. It polls the interface sniffers and interacts with them"""
        self._loop = loop
        self._update_ip_addresses()



    def _update_ip_addresses(self, loop=None, user_data=None):
        ip_labels = []
        ips = []
        interfaces = []

        traffic_sniffers = self._interface_selector.get_traffic_sniffers()

        # Get the list of interfaces, and the network IPs they are collecting
        for interface in traffic_sniffers:
            for ip in traffic_sniffers[interface].get_sniffed_ips():
                ip_str = socket.inet_ntoa(ip).ljust(15, ' ')
                ip_labels.append(ip_str + " - " + interface)
                ips.append(ip)
                interfaces.append(interface)

        cb_to_remove = []
        cb_list = []

        # Remove CheckBoxes for IPs that are not sniffed anymore
        for cb in self._ip_addresses_walker:
            if (cb.get_label() not in ip_labels):
                cb_to_remove.append(cb)
            else:
                cb_list.append(cb.get_label())

        for cb in cb_to_remove:
            self._logger.debug("Removing IP checkbox %s" % cb.get_label())
            self._ip_addresses_walker.remove(cb)

        # Add Checkboxes for new IPs
        for ip_id in range(len(ip_labels)):
            ip_label = ip_labels[ip_id]
            ip = ips[ip_id]
            interface = interfaces[ip_id]

            if (ip_label not in cb_list):
                self._logger.debug("Adding IP checkbox %s" % ip_label)
                self._ip_addresses_walker.append(urwid.CheckBox(ip_label, False, False, self._action_ip_selected, [ip, interface]))

        self._ip_addresses_walker.sort(key=lambda x : x.get_label())
        
        self._loop.set_alarm_in(1, self._update_ip_addresses)
    
    

    def _action_ip_selected(self, check_box, selected, data):
        ip = data[0]
        ip_label = socket.inet_ntoa(ip)
        interface = data[1]

        if (selected):
            title = "Do you expect IP %s - %s to behave as an IoT?" % (ip_label, interface)
            popup.Dialog(self._main_frame, title, ["Yes", "No", "Cancel"], self._action_expect_device_iot, [[ip, interface, True], [ip, interface, False], [check_box]])
        else:
            self._interface_selector.get_traffic_sniffers()[interface].remove_ip_to_filter(ip)
            self._lock.acquire()
            if (interface in self._collected_data):
                self._collected_data[interface].pop(ip, None)
            self._lock.release()



    def _action_expect_device_iot(self, data):
        # If the user selected "Cancel", deselect the checkbox
        if (len(data) < 3):
            data[0].set_state(False)
            return
        
        ip = data[0]
        interface = data[1]
        expected_iot = data[2]

        self._lock.acquire()
        
        if (interface not in self._collected_data):
            self._collected_data[interface] = {}

        self._collected_data[interface][ip] = [expected_iot, 0, 0]
        self._lock.release()
        
        self._logger.info("Added a filter for ip %s-%s. The user expects it to be an IOT? %s" % (ip, interface, expected_iot))
        self._interface_selector.get_traffic_sniffers()[interface].add_ip_to_filter(ip, TraceWriter(expected_iot, ip, self._sampling_seconds, self._memory_seconds))

    

    def get_list_box(self):
        return urwid.ListBox(self._ip_addresses_walker)
    
    
    
    def get_collected_data(self):
        self._lock.acquire()
        expected_data_copy = dict(self._collected_data)
        self._lock.release()
        
        return expected_data_copy
