
import os
import csv
import captcp
import hashlib
import logging

class FeatureParser():
    """This class parses pcap files and generates an output file containing a 
    summary of the data features. The rationale for having one such class is 
    mostly for performance (and debugging) issues.

    It is meant to recursively parse all the files in the subdirectory provided 
    as input.

    The output of the computation is a list of flows, with the associated set 
    of features extracted with captcp.

    A flow is the four tuple:
        src_ip : src_tcp_port -> dst_ip : dst_tcp_port

    It is possible to add filters for the flows, by restricting their sets
    to those matching on a specific srcMAC / dstMAC address. This information
    is provided in an external "feature_parser.csv" file (one for each 
    subdirectory parsed).

    The format of the "feature_parser.csv" file is as follows:

    PCAP File Name;SRC MAC ADDRESS filter;DST MAC ADDRESS filter

    Please note that every field in the CSV is optional (in case that a value 
    is missing it will be interpreted as a wild-card).

    INPUT examples for the "feature_parser.csv" file:

    - ;;    : Parse every flow in every .pcap file in the current directory
    - f1.pcap;;00:00:00:00:00:01 : In file f1.pcap, parse all the flows with
            destination MAC addess 00:00:00:00:00:01
    - An empty (or nonexistant) "feature_parser.csv" file, prevents the 
             FeatureParser to extract the data in that directory
   
    OUTPUT:

    For each .pcap file in the current directory a .dat file is produced.
    The .dat file is essentially a CSV file that contains the parsed
    features for every flow in the corresponding .pcap file. 

    In order to gracefully handle changes to the "feature_parser.csv" as
    well as the .pcap files, the first line of the .dat file contains
    the SHA1 of the "feature_parser.csv" file, as well as the SHA1 of
    the corresponding .pcap file, generated when the .dat file was 
    created. They will be used to automatically update the .dat files.

    In case that a .pcap file is missing, and the .dat file is instead
    available, the parser won't delete the .dat file.

    One .dat file is produced for each .pcap file, and they have the 
    same name.
    
    USAGE EXAMPLE:
    
    To recursively parse the PCAPS folder
    fp = FeatureParser('PCAPS')
    features = fp.extract_features()
    """
    
    # TODO: the output file should contain the following information at the
    # beginning of each line: pcapFILEname.pcap;SRCMacAddr;DSTMacAddr; then all 
    # the others
    
    FEATURE_PARSER_FILE_NAME = "feature_parser.csv"

    def __init__(self, path):
        self.path = path
        self.logger = logging.getLogger(__name__)

    def extract_features(self):
        features = []
        for root, dirnames, files in os.walk(self.path):
            if (FeatureParser.FEATURE_PARSER_FILE_NAME in files):
                files = filter(lambda x: x[-5:] == ".pcap", files)
                dat_file_filters = self.parse_pcap_files(root, files)
                features.extend(self.get_features(dat_file_filters))
        return features
                

    def parse_pcap_files(self, folder, files):
        flow_classes = self.parse_flow_classes(folder)
        (pcap_file_filters, dat_file_filters) = self.extract_file_filters(folder, files, flow_classes)
        features = self.extract_file_features(pcap_file_filters)
        self.persist_features(features)
        return dat_file_filters

    def parse_flow_classes(self, folder):
        file_path = os.path.join(folder, FeatureParser.FEATURE_PARSER_FILE_NAME)

        fc_data = []

        with open(file_path, "rb") as csvfile:
            fc_reader = csv.reader(csvfile, delimiter=";", quotechar="|")

            for row in fc_reader:
                fc_row = {'pcap_file': row[0], 'src_mac': row[1], 'dst_mac': row[2]}
                for k in fc_row.keys():
                    if (fc_row[k] == ''):
                        fc_row[k] = None
                fc_data.append(fc_row)

        return fc_data

    def extract_file_filters(self, folder, files, flow_classes):
        flow_classes_sha1 = self.get_hash(os.path.join(folder, FeatureParser.FEATURE_PARSER_FILE_NAME))
        pcap_files_sha1 = {}
        
        pcap_file_filters = {}
        dat_file_filters = {}
        
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
                
                dat_file_filters[dat_file_path] = 1
                
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
                    
                    dat_file_filters[dat_file_path] = 1
                    
                    if (self.file_hashes_not_changed(dat_file_path, pcap_file_path, 
                                pcap_files_sha1, flow_classes_sha1)):
                        continue
                    
                    pcap_file_filters[pcap_file_path]['should-parse'] = True
                    pcap_file_filters[pcap_file_path]['filters'].append(fc_filter)

        return (pcap_file_filters, dat_file_filters)
    
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
                    flow_features = [i.smac, i.dmac, i.sip, i.dip, i.sport, i.dport]

                    for lbl in captcp.STATISTIC_LABELS:
                        flow_features.append(i.user_data[lbl])

                    file_features.append(flow_features)

                features[file_path] = file_features
        return features

    def persist_features(self, features):
        for file_path in features.keys():
            path_root = os.path.dirname(file_path)
            flow_classes_path = os.path.join(path_root, FeatureParser.FEATURE_PARSER_FILE_NAME)

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

    def get_features(self, dat_file_filters):
        features = []
        
        for dat_file_path in dat_file_filters.keys():
            if (dat_file_filters[dat_file_path] == 1):
                with open(dat_file_path) as dat_file:
                    dat_file.readline()
                    dat_file.readline()
                    
                    dat_file_reader = csv.reader(dat_file, delimiter=";", quotechar="|")
                    
                    for row in dat_file_reader:
                        features.append(row) 

        return features



fp = FeatureParser('PCAPS')
features = fp.extract_features()
for i in features:
    print i
