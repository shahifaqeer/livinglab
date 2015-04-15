import urwid

class AggregateStatsViewer():

    """This class shows the aggregate set of statistics. 
    """
    def __init__(self, main_frame, sampling_seconds, ip_selector, decision_tree):
        self._main_frame = main_frame
        self._sampling_seconds = sampling_seconds
        self._ip_selector = ip_selector
        self._decision_tree = decision_tree

        self._list_walker = urwid.SimpleListWalker([])

        self._samples_iot = 0
        self._samples_non_iot = 0
        self._correct_samples_iot = 0
        self._correct_samples_non_iot = 0



    def get_list_box(self):
        return urwid.ListBox(self._list_walker)



    def attach_to_loop(self, loop):
        """Makes sure that periodically the set of statistics for each IP
        is updated"""
        self._loop = loop
        self._sample_data()



    def add_sample(self, expected_iot):
        if (expected_iot):
            self._samples_iot += 1
        else:
            self._samples_non_iot += 1


    def add_correct_sample(self, expected_iot):
        if (expected_iot):
            self._correct_samples_iot += 1
        else:
            self._correct_samples_non_iot += 1



    def _sample_data(self, loop=None, user_data=None):
        if (self._samples_iot == 0):
            iot_accuracy = 0
        else:
            iot_accuracy = 100 * self._correct_samples_iot / self._samples_iot

        if (self._samples_non_iot == 0):
            non_iot_accuracy = 0
        else:
            non_iot_accuracy = 100 * self._correct_samples_non_iot / self._samples_non_iot

        self._list_walker[:] = []

        self._list_walker.append(urwid.Text("Sample features for IoT:      %d" % self._decision_tree.get_num_iot_definitions()))
        self._list_walker.append(urwid.Text("Sample features for non-IoT:  %d" % self._decision_tree.get_num_non_iot_definitions()))
        self._list_walker.append(urwid.Text("Overall accuracy for IoT:     %d%%" % iot_accuracy))
        self._list_walker.append(urwid.Text("Overall accuracy for non-IoT: %d%%" % non_iot_accuracy))

        self._loop.set_alarm_in(self._sampling_seconds, self._sample_data)

