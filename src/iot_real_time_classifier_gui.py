import urwid
import logging
import argparse
from decision_tree import DecisionTree

from gui.interface_selector import NetworkInterfaceSelector
from gui.ip_selector import IPSelector
from gui.ip_stats_viewer import IPStatsViewer
from gui.aggregate_stats_viewer import AggregateStatsViewer

class IoTClassifierGUI():

    def __init__(self):
        self._sampling_seconds = 1
        self._memory_seconds = 60
        self._features_lag = 6
        self._max_tree_depth = None

        self._parse_cli_params()

        self._net_selector = None
        self._ip_selector = None
        self._ip_stats_viewer = None

        self._iot_classifier_dt = DecisionTree(self._sampling_seconds, self._memory_seconds, self._features_lag, self._max_tree_depth)

        self._main_frame = urwid.Frame(urwid.Filler(urwid.Text(""), "top"))

        self._logger = logging.getLogger(__name__)



    def _parse_cli_params(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", help="Sampling seconds parameter", type=int)
        parser.add_argument("-m", help="Memory seconds parameter", type=int)
        parser.add_argument("-f", help="Features lag parameter", type=int)
        parser.add_argument("-d", help="Maximum tree depth. DEFAULT Unbounded", type=int)
        parser.add_argument("--debug", help="Log debug messages", action="count", default=0)
        args = parser.parse_args()
        
        if (args.debug > 0):
            logging.basicConfig(filename='gui.log', level=logging.DEBUG)
        else:
            logging.basicConfig(filename='gui.log', level=logging.INFO)
        
        if (args.f is not None):
            self._features_lag = int(args.f)
        
        if (args.m is not None):
            self._memory_seconds = int(args.m)
            
        if (args.s is not None):
            self._sampling_seconds = int(args.s)

        if (args.d is not None):
            self._max_tree_depth = int(args.d)
            
        

    def _show_or_exit(self, key):
        if key in ['q', 'Q']:
            self._net_selector.terminate()
            raise urwid.ExitMainLoop()



    def run(self):
        palette = [
                    ("header", "white", "dark red"),
                    ("footer", "light red", "black"),
                  ]

        self._net_selector = NetworkInterfaceSelector(self._main_frame, self._memory_seconds, self._features_lag)
        self._ip_selector = IPSelector(self._main_frame, self._sampling_seconds, self._memory_seconds, self._net_selector)
        self._aggregate_stats = AggregateStatsViewer(self._main_frame, self._sampling_seconds, self._ip_selector, self._iot_classifier_dt)
        self._ip_stats_viewer = IPStatsViewer(self._main_frame, self._sampling_seconds, self._net_selector, self._ip_selector, self._iot_classifier_dt, self._aggregate_stats)

        header_text = urwid.Text(("header", "IoT Classifier v0.1 - Press \"q\" to Exit"), align="center")
        head = urwid.AttrMap(header_text, "header")

        tree_depth = "Unbounded"
        if (self._max_tree_depth is not None):
            tree_depth = self._max_tree_depth

        self._footer_text = urwid.Text("Sampling seconds: %d, Memory seconds: %d, Features lag: %d, Max tree depth: %s" % (self._sampling_seconds, self._memory_seconds, self._features_lag, tree_depth), align="left")
        foot = urwid.AttrMap(self._footer_text, "footer")

        interfaces_box = urwid.LineBox(self._net_selector.get_list_box(), title="Interfaces")
        aggregate_stats_box = urwid.LineBox(self._aggregate_stats.get_list_box(), title="Aggregate Statistics")
        ip_addresses_box = urwid.LineBox(self._ip_selector.get_list_box(), title="Tracking IP Addresses")
        ip_statistics_box = urwid.LineBox(self._ip_stats_viewer.get_list_box(), title="IP Statistics")

        left_column = urwid.Pile([("fixed", 7, interfaces_box), ip_addresses_box])
        right_column = urwid.Pile([("fixed", 7, aggregate_stats_box), ip_statistics_box])

        main_cols = urwid.Columns([left_column, right_column])

        self._main_frame.contents["body"] = (main_cols, None)
        self._main_frame.contents["header"] = (head, None)
        self._main_frame.contents["footer"] = (foot, None)

        self._loop = urwid.MainLoop(self._main_frame, palette,
                              unhandled_input=self._show_or_exit)

        self._net_selector.attach_to_loop(self._loop)
        self._ip_selector.attach_to_loop(self._loop)
        self._ip_stats_viewer.attach_to_loop(self._loop)
        self._aggregate_stats.attach_to_loop(self._loop)

        self._loop.run()



if (__name__ == "__main__"):
    gui = IoTClassifierGUI()
    gui.run()
