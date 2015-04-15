import urwid
import utils
import sniffer
import logging
import threading

class NetworkInterfaceSelector():
    """This class implements the behavior of the network interface selector.
    It periodically scans the available network interfaces on the system, and 
    updates their list adding the corresponding actions to the GUI.
    
    It also initializes the InterfaceSniffers, accordingly.
    """
    def __init__(self, main_frame, memory_seconds, features_lag):
        self._main_frame = main_frame
        self._memory_seconds = memory_seconds
        self._features_lag = features_lag

        self._traffic_sniffers = {}
        self._interface_sniffers = {}
        self._interface_buttons = {}

        self._list_walker = urwid.SimpleListWalker([])
        self._loop = None
        self._lock = threading.Lock()

        self._logger = logging.getLogger(__name__)



    def attach_to_loop(self, loop):
        """Makes sure that the network interface list is updated periodically. 
        It changes the interface sniffers according to the state
        of the network interfaces."""
        self._loop = loop
        self._run_loop()



    def _run_loop(self, loop=None, user_data=None):
        net_interfaces = utils.list_interfaces()

        interfaces_to_remove = []

        # Mark interfaces to remove
        for previous_net_interface in self._interface_buttons:
            found = False
            for new_net_interface in net_interfaces:
                if (new_net_interface[0] == previous_net_interface):
                    found = True
                    break

            if (not found):
                interfaces_to_remove.append(previous_net_interface)

        # Remove interfaces deactivating the sniffers associated
        for net_interface in interfaces_to_remove:
            self._logger.info("Network interface %s is not available anymore" % net_interface)

            checkbox = self._interface_buttons[net_interface]
            self._list_walker.remove(checkbox)

            self._lock.acquire()
            if (net_interface in self._traffic_sniffers):
                self._traffic_sniffers[net_interface].terminate()
                self._traffic_sniffers.pop(net_interface, None)
                self._interface_buttons.pop(net_interface)
            self._lock.release()

        # Add new interfaces
        for net_interface in net_interfaces:
            if (net_interface[0] not in self._interface_buttons):
                self._logger.info("Adding network interface %s - %s" % (net_interface[0], net_interface[1]))
                checkbox = urwid.CheckBox("%s - %s" % (net_interface[0], net_interface[1]), False, False, self._action_interface_update, net_interface[0])
                self._list_walker.append(checkbox)
                self._interface_buttons[net_interface[0]] = checkbox

        # Attach to loop
        self._loop.set_alarm_in(1, self._run_loop)



    def _action_interface_update(self, check_box, selected, interface):
        self._lock.acquire()
        if (selected):
            if (interface not in self._traffic_sniffers):
                # Create and start thread
                self._traffic_sniffers[interface] = sniffer.InterfaceSniffer(interface, self._main_frame, self._memory_seconds, self._features_lag)
                self._traffic_sniffers[interface].start()

            self._traffic_sniffers[interface].do_start()

            self._logger.debug("Selected interface %s" % interface)
        else:
            self._traffic_sniffers[interface].terminate()
            self._traffic_sniffers.pop(interface, None)
            self._logger.debug("Deselected interface %s" % interface)
        self._lock.release()



    def get_list_box(self):
        """Returns the list box. It makes it possible to update the 
        list of interfaces at regular intervals"""
        return urwid.ListBox(self._list_walker)



    def terminate(self):
        """It gracefully stops the interface sniffers"""

        self._lock.acquire()
        for interface in self._traffic_sniffers:
            self._logger.info("Gracefully terminating sniffers on interface %s" % interface)
            sniffer = self._traffic_sniffers[interface]
            sniffer.terminate()
        self._lock.release()



    def get_traffic_sniffers(self):
        self._lock.acquire()
        sniffers_copy = dict(self._traffic_sniffers)
        self._lock.release()

        return sniffers_copy
