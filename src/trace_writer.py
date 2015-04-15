import socket
import time
import os
import errno
import logging

class TraceWriter():
    """
    This class writes the collected traces to an output file in the correct
    directory, according to the data provided by the user.
    
    DAT files are organized using the following directory structure:
    
    trace/IoT/TIMESTAMP_IP_(sampling_seconds)_(memory_seconds).dat
    trace/non-IoT/TIMESTAMP_IP_(sampling_seconds)_(memory_seconds).dat
    """
    
    def __init__(self, expected_iot, ip, sampling_seconds, memory_seconds):
        self._logger = logging.getLogger(__name__)
        self._expected_iot = expected_iot
        self._ip = socket.inet_ntoa(ip)
        self._timestamp = int(time.time())
        self._sampling_seconds = sampling_seconds
        self._memory_seconds = memory_seconds
        self._file_path = self._get_file_path()
        self._f = open(self._file_path, 'wb')
       
       
        
    def _get_file_path(self):
        path = None
        
        if (self._expected_iot):
            path = "trace/IoT/"
        else:
            path = "trace/non-IoT/"
        
        path = "%s%d_%s_%d_%d.dat" % (path, self._timestamp, self._ip,
                                      self._sampling_seconds, self._memory_seconds)
        
        TraceWriter._recursively_create_dirs(path)
        
        self._logger.info("Logging data to: %s" % path)
        
        return path
       
       
       
    @staticmethod
    def _recursively_create_dirs(file_path):
        """
        Creates the directories if they do not exist
        """
        try:
            os.makedirs(os.path.dirname(file_path))
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
       
       
        
    def close_file(self):
        self._logger.info("Gracefully closing log file %s" % self._file_path)
        self._f.close()
       
       
        
    def append_feature(self, feature):
        self._f.write("%d\n" % feature[-1])
