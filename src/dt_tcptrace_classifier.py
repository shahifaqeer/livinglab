from sklearn import tree
from sklearn.externals.six import StringIO
from subprocess import call
import os
import csv
from random import randint

"""
This file contains functions to run the Decision Tree Classifier on 
data extracted with tcptrace. 

EXAMPLE:

    test_dt('PCAP', 0.70, 10)
"""
class ConnectionRecord():
    """This class represents one connection record as in tcptrace"""

    def __init__(self, row):
        self.host_a = row[1]
        self.host_b = row[2]
        self.port_a = int(row[3])
        self.port_b = int(row[4])
        self.first_packet = float(row[5])
        self.last_packet = float(row[6])
        self.time = self.last_packet - self.first_packet
        self.total_packets_a2b = int(row[7])
        self.total_packets_b2a = int(row[8])
        self.actual_data_pkts_a2b = int(row[23])
        self.actual_data_pkts_b2a = int(row[24])
        self.actual_data_bytes_a2b = int(row[25])
        self.actual_data_bytes_b2a = int(row[26])
        self.idletime_max_a2b = float(row[83])
        self.idletime_max_b2a = float(row[84])
        self.throughput_a2b = float(row[87])
        self.throughput_b2a = float(row[88])

    def get_selected_features(self):
        return [self.port_a, self.port_b, self.time, self.total_packets_a2b, self.total_packets_b2a, self.actual_data_pkts_a2b, self.actual_data_pkts_b2a, self.actual_data_bytes_a2b, self.actual_data_bytes_b2a, self.idletime_max_a2b, self.idletime_max_b2a, self.throughput_a2b, self.throughput_b2a]

    def __str__(self):
        return "%s:%d <-> %s:%d, time %f s, # packets s->d %d, d->s %d, # data packets s->d %d, d->s %d, bytes s->d %d, d->s %d, idletime s->d %f, d->s %f, throughput s->d %f, d->s %f" % (self.host_a, self.port_a, self.host_b, self.port_b, self.time, self.total_packets_a2b, self.total_packets_b2a, self.actual_data_pkts_a2b, self.actual_data_pkts_b2a, self.actual_data_bytes_a2b, self.actual_data_bytes_b2a, self.idletime_max_a2b, self.idletime_max_b2a, self.throughput_a2b, self.throughput_b2a)

    def __repr__(self):
        return self.__str__()



def print_output(classes, num_of_samples, test_data, num_recognized_samples):

    total_num_of_samples = 0
    total_recognized_samples = 0
    total_test_data = 0

    for i in num_of_samples:
        total_num_of_samples = total_num_of_samples + i

    for t in num_recognized_samples:
        total_recognized_samples = total_recognized_samples + t

    for t in test_data:
        total_test_data = total_test_data + len(t)
        
    training_samples = total_num_of_samples - total_test_data
    
    print "OUTPUT:\nTraining classes: %d" % len(classes)
    print "Total number of samples: %d" % total_num_of_samples
    print "Training samples used: %d/%d (%f %%)" % (training_samples, total_num_of_samples, 100 * training_samples / total_num_of_samples)
    print "Test samples successfully recognized: %d/%d (%f %%)" % (total_recognized_samples, total_test_data, 100 * total_recognized_samples / total_test_data)

    print "\nDETAIL:\n"

    for i in range(len(classes)):
        c = classes[i]
        print "- Class: %d" % c[0]
        print "  Test samples successfully recognized: %d/%d (%f %%)\n" % (num_recognized_samples[i], len(test_data[i]), 100*num_recognized_samples[i]/len(test_data[i]))



def classify_data(decision_tree, test_data, expected_class):
    recognized_samples = 0

    for t in test_data:
        if (decision_tree.predict(t.get_selected_features()) == expected_class):
            recognized_samples = recognized_samples + 1

    return recognized_samples



def get_tcptrace_data(pcap_file):
    """Returns the data processed with tcptrace on the PCAP file 
    provided as input parameter."""
    output_file_name = pcap_file[:-5] + "_tcptrace.csv"
    call("tcptrace -Dnlc --csv " + pcap_file +  " > " + output_file_name, shell=True)

    data = []

    with open(output_file_name, 'rb') as file_csv:
        # Skip the first lines with comments and column header
        pos = 0
        c = file_csv.read(1)
        while c != '1':
            if (c != '\n' and c != ''):
                file_csv.readline()
            elif (c == ''):
                return []
            pos = file_csv.tell()
            c = file_csv.read(1)
        
        file_csv.seek(pos)

        trace_reader = csv.reader(file_csv, delimiter=',')

        for row in trace_reader:
            data.append(ConnectionRecord(row))

    return data



def get_train_data(decision_tree, curr_class, fraction_of_training_samples):
    test_data_in_class = []
    tcp_trace_data = []

    for f in curr_class[1]:
        tcp_trace_data.extend(get_tcptrace_data(f))

    num_of_samples = len(tcp_trace_data)
    num_of_test_samples = int(num_of_samples * (1-fraction_of_training_samples))
    test_samples_ids = []

    while (len(test_samples_ids) < num_of_test_samples):
        q = randint(0, num_of_samples-1)
        while q in test_samples_ids:
            q = randint(0, num_of_samples-1)
        test_samples_ids.append(q)

    for i in test_samples_ids:
        test_data_in_class.append(tcp_trace_data[i])

    test_samples_ids = sorted(test_samples_ids, reverse=True)

    for i in test_samples_ids:
        tcp_trace_data.pop(i)

    return (num_of_samples, test_data_in_class, tcp_trace_data, [curr_class[0]] * len(tcp_trace_data))



def get_classes(folder):
    """Recursively explores all the subfolders and return them only if 
    finds a .pcap file in it"""
    classes = []
    
    class_id = 0
    
    for root, subdirs, files in os.walk(folder):
        files_detected = []
        for f in files:
            if (f[-5:] == ".pcap"):
                files_detected.append(os.path.join(root, f))

        if (len(files_detected) > 0):
            class_id = class_id + 1
            classes.append((class_id, files_detected))

    return classes



def test_dt(folder, fraction_of_training_samples, max_tree_depth = 5):
    """This function tests the decision tree classifier. Only a fraction 
    of the samples will be used to train the DT. Each subfolder is a new
    class."""

    classes = get_classes(folder)
    dt = tree.DecisionTreeClassifier(max_depth=max_tree_depth)

    samples_per_class = []
    test_data = []
    train_data = []
    train_classes = []
    num_recognized_samples = []

    for cl_id in range(len(classes)):
        cl = classes[cl_id]
        (num_of_samples, test_data_in_class, train_data_in_class, expected_class) = get_train_data(dt, cl, fraction_of_training_samples)
        samples_per_class.append(num_of_samples)
        test_data.append(test_data_in_class)
        train_data.extend(train_data_in_class)
        train_classes.extend(expected_class)
        
    td_array = []
    
    for t in train_data:
        td_array.append(t.get_selected_features())

    dt.fit(td_array, train_classes)

    for cl_id in range(len(classes)):
        cl = classes[cl_id]
        current_num_recognized_samples = classify_data(dt, test_data[cl_id], cl[0])
        num_recognized_samples.append(current_num_recognized_samples) 

    print_output(classes, samples_per_class, test_data, num_recognized_samples)


