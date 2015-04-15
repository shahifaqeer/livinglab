import logging
import os
from sklearn import tree

class DecisionTree():
    """This class represents a decision tree classifier for IoT devices. It is
    used to train a DT using the number of unique ips as a feature between an 
    IoT device and a non-IoT. 

    It parses the .dat files produced in other analysis.

    It expects the following input parameters:

    - sampling_seconds: the sampling frequency
    - memory_seconds: the length of the memory
    - features_lag: the number of consecutive time slots used to generate the
                    features
    - dt_depth: the maximum depth of the decision tree
    
    DAT files must be organized using the following directory structure:
    
    trace/IoT/TIMESTAMP_IP_(sampling_seconds)_(memory_seconds).dat
    trace/non-IoT/TIMESTAMP_IP_(sampling_seconds)_(memory_seconds).dat
    
    It is not mandatory to provide traffic traces. In that case, the default 
    answer is having a 50% probability for being IoT and 50% for not being 
    as such.
    """

    IOT_CLASS_ID = 1
    NON_IOT_CLASS_ID = 0

    DEFAULT_IOT_TRACE_PATH = "trace/IoT"
    DEFAULT_NON_IOT_TRACE_PATH = "trace/non-IoT"



    def __init__(self, sampling_seconds, memory_seconds, features_lag,
            dt_depth=None):
        print "Training the decision tree. Please wait..."
        self._logger = logging.getLogger(__name__)

        self._dt_depth = dt_depth

        self.sampling_seconds = sampling_seconds
        self.memory_seconds = memory_seconds
        self.features_lag = features_lag

        self._num_iot_definitions = 0
        self._num_non_iot_definitions = 0

        self._dt = None

        self._train()
        self._iot_class = None
        
        if (self._dt is not None):
            for i in range(len(self._dt.classes_)):
                if (self._dt.classes_[i] == DecisionTree.IOT_CLASS_ID):
                    self._iot_class = i
                    break



    def _train(self):
        (X, Y) = self._generate_data_samples()

        info = ("Training decision tree. Sampling seconds %f"
                " - Memory seconds %f - Features lag %f - Max depth %s. "
                "Number of samples: %d")

        self._logger.info(info % (self.sampling_seconds, self.memory_seconds,
                                  self.features_lag, self._dt_depth, len(X)))

        if (len(X) > 0):
            self._dt = tree.DecisionTreeClassifier(max_depth=self._dt_depth)
            self._dt.fit(X, Y)



    def _generate_data_samples(self):
        X_iot = self._parse_dat_files(DecisionTree.DEFAULT_IOT_TRACE_PATH)
        X_non_iot = self._parse_dat_files(DecisionTree.DEFAULT_NON_IOT_TRACE_PATH)
        
        self._num_iot_definitions = len(X_iot)
        self._num_non_iot_definitions = len(X_non_iot)

        self._logger.info("Loaded %d definitions for IoT devices" % self._num_iot_definitions)
        self._logger.info("Loaded %d definitions for non-IoT devices" % self._num_non_iot_definitions)

        Y_iot = [DecisionTree.IOT_CLASS_ID] * len(X_iot)
        Y_non_iot = [DecisionTree.NON_IOT_CLASS_ID] * len(X_non_iot)

        X = X_iot
        Y = Y_iot

        X.extend(X_non_iot)
        Y.extend(Y_non_iot)

        return (X, Y)



    def _parse_dat_files(self, folder):
        files = self._get_dat_files_in_folder(folder)

        features_array = []

        for f in files:
            feature = [-1] * self.features_lag
            with open(f, 'rb') as dat_file:
                for l in dat_file.readlines():
                    feature.append(int(l))
                    feature.pop(0)
                    features_array.append(list(feature))

        return features_array



    def _get_dat_files_in_folder(self, folder):
        file_paths = []

        file_name_ending = "_%d_%d.dat" % (self.sampling_seconds, self.memory_seconds)

        for root, subdirs, files in os.walk(folder):
            for f in files:
                if (f.endswith(file_name_ending)):
                    file_paths.append(os.path.join(root, f))

        return file_paths



    def is_iot(self, data):
        return self.iot_probability(data) >= 0.5



    def iot_probability(self, data):
        if (self._dt is not None):
            if (self._iot_class is None):
                return 0
            else:
                return self._dt.predict_proba(data)[0][self._iot_class]
        else:
            return 0.5
    

    
    def get_num_iot_definitions(self):
        return self._num_iot_definitions

    
    
    def get_num_non_iot_definitions(self):
        return self._num_non_iot_definitions
