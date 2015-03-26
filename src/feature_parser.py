
import os
import csv
import captcp
import hashlib
import logging

class FeatureParser():
    """This class parses pcap files and generates an output file containing a 
    summary of the data features. The rationale for having one such class is 
    mostly for performance (and debugging) issues.

    It is meant to parse recursively parse all the files in the subdirectory
    provided as input.

    The output of the computation is a list of flows, with the associated set 
    of features extracted with captcp.

    A flow is the four tuple:
        src_ip : src_tcp_port -> dst_ip : dst_tcp_port

    It is possible to add filters for the flows, by restricting their sets
    to those matching on a specific srcMAC / dstMAC address. This information
    is provided in an external "flow_classifier.csv" file (one for each 
    subdirectory parsed).

    The format of the "flow_classes.csv" file is as follows:

    PCAP File Name;SRC MAC ADDRESS filter;DST MAC ADDRESS filter;Flow class ID

    Please note that every field in thcaptcpe CSV is optional (in case that a value 
    is missing it will be interpreted as a wild-card).

    The flow class ID is an external integer number (provided by the user)
    and it can be used during the training phase of the ML algorithm.

    INPUT examples for the "flow_classes.csv" file:

    - ;;;1 : For every .pcap file in the current directory and every flow, 
             assign the Flow class ID 1
    - ;;;  : For every .pcap file in the current directory, parse every
             flow, without assigning any Flow class ID
    - f1.pcap;;00:00:00:00:00:01;3 : Assign the Flow class ID 3 to all the
             flows in file f1.pcap with dst mac address 00:00:00:00:00:01
    - An empty (or nonexistant) "flow_classes.csv" file, prevents the 
             FeatureParser to extract the data in that directory
   
    OUTPUT:

    For each .pcap file in the current directory a .dat file is produced.
    The .dat file is essentially a CSV file that contains the parsed
    features for every flow in the corresponding .pcap file. 

    In order to gracefully handle changes to the "flow_classes.csv" as
    well as the .pcap files, the first line of the .dat file contains
    the SHA1 of the "flow_classes.csv" file, as well as the SHA1 of
    the corresponding .pcap file, generated when the .dat file was 
    created. They will be used to automatically update the .dat files.

    In case that a .pcap file is missing, and the .dat file is instead
    available, the parser won't delete the .dat file.

    One .dat file is produced for each .pcap file, and they have the 
    same name.
    """

    def __init__(self, path):
        self.path = path
        self.logger = logging.getLogger(__name__)

    def extract_features(self):
        for root, dirnames, files in os.walk(self.path):
            if ("flow_classes.csv" in files):
                files = filter(lambda x: x[-5:] == ".pcap", files)
                self.process_folder(root, files)

    def process_folder(self, folder, files):
        flow_classes = self.parse_flow_classes(folder)
        file_filters = self.extract_file_filters(folder, files, flow_classes)
        features = self.extract_file_features(file_filters)
        self.persist_features(features)

    def parse_flow_classes(self, folder):
        file_path = os.path.join(folder, "flow_classes.csv")

        fc_data = []

        with open(file_path, "rb") as csvfile:
            fc_reader = csv.reader(csvfile, delimiter=";", quotechar="|")

            for row in fc_reader:
                fc_row = {'pcap_file': row[0], 'src_mac': row[1], 'dst_mac': row[2], 'class_id': row[3]}
                for k in fc_row.keys():
                    if (fc_row[k] == ''):
                        fc_row[k] = None
                fc_data.append(fc_row)

        return fc_data

    def extract_file_filters(self, folder, files, flow_classes):
        flow_classes_sha1 = self.get_hash(os.path.join(folder, "flow_classes.csv"))
        pcap_files_sha1 = {}
        pcap_file_filters = {}
        
        for f in files:
            pcap_file_path = os.path.join(folder,f)
            pcap_file_filters[pcap_file_path] = {'should-parse': False, 'filters': []}
            pcap_files_sha1[pcap_file_path] = self.get_hash(pcap_file_path)
    
        # Handle file wildcards
        for fc in flow_classes:
            pcap_file = fc["pcap_file"]
            fc_filter = [fc["src_mac"], fc["dst_mac"]]

            if (pcap_file != None):
                pcap_file_path = os.path.join(folder, pcap_file)
                dat_file_path = os.path.join(folder, pcap_file[:-5] + ".dat")
                
                if (self.file_hashes_not_changed(dat_file_path, pcap_file_path, 
                                pcap_files_sha1, flow_classes_sha1)):
                        continue

                try:
                    pcap_file_filters[pcap_file_path]['should-parse'] = True
                    pcap_file_filters[pcap_file_path]['filters'].append(fc_filter)
                except KeyError:
                    print "File: %s not found in folder: %s" % (pcap_file, folder)
            else:
                for f in files:
                    pcap_file_path = os.path.join(folder, f)
                    dat_file_path = os.path.join(folder, f[:-5] + ".dat")
                    
                    if (self.file_hashes_not_changed(dat_file_path, pcap_file_path, 
                                pcap_files_sha1, flow_classes_sha1)):
                        continue
                    
                    pcap_file_filters[pcap_file_path]['should-parse'] = True
                    pcap_file_filters[pcap_file_path]['filters'].append(fc_filter)

        return pcap_file_filters
    
    def file_hashes_not_changed(self, dat_file_path, pcap_file_path, 
                                pcap_files_sha1, flow_classes_sha1):
        if (os.path.exists(dat_file_path)):
            with open(dat_file_path, "rb") as dat_file:
                file_path_old_sha1 = dat_file.readline().rstrip('\n')
                flow_classes_old_sha1 = dat_file.readline().rstrip('\n')
                
                if (file_path_old_sha1 == pcap_files_sha1[pcap_file_path] and 
                    flow_classes_old_sha1 == flow_classes_sha1):
                    return True
        return False

    def extract_file_features(self, file_filters):
        features = {}

        for file_path in file_filters.keys():
            if (file_filters[file_path]['should-parse']):
                file_features = []
                
                self.logger.debug("Parsing PCAP file: %s" % file_path)

                ctcp = captcp.Captcp(file_path)

                for fc_filter in file_filters[file_path]['filters']:
                    ctcp.add_filter(fc_filter[0], fc_filter[1])

                ctcp.run()
                
                for i in ctcp.get_subconnections_stats():
                    flow_features = [i.sip, i.dip, i.sport, i.dport]

                    for lbl in captcp.STATISTIC_LABELS:
                        flow_features.append(i.user_data[lbl])

                    file_features.append(flow_features)

                features[file_path] = file_features
        return features

    def persist_features(self, features):
        for file_path in features.keys():
            path_root = os.path.dirname(file_path)
            flow_classes_path = os.path.join(path_root, "flow_classes.csv")

            file_path_sha1 = self.get_hash(file_path)
            flow_classes_sha1 = self.get_hash(flow_classes_path)

            with open(file_path[:-5] + ".dat", "wb") as dat_file:
                dat_file.write(file_path_sha1 + '\n')
                dat_file.write(flow_classes_sha1 + '\n')

                csv_writer = csv.writer(dat_file, delimiter=";", 
                        quotechar="|", quoting=csv.QUOTE_MINIMAL)

                for flow_feature in features[file_path]:
                    csv_writer.writerow(flow_feature)
    
    def get_hash(self, filepath):
        """Returns the SHA1 hash of the file passed as a parameter"""

        h = hashlib.sha1()
        with open(filepath, 'rb') as f:
            chunk = 0
            while chunk != b'':
                chunk = f.read(1024)
                h.update(chunk)

        return h.hexdigest()

# USAGE EXAMPLE:
# to recursively parse the PCAPS folder
# fp = FeatureParser('PCAPS')
# fp.extract_features()

