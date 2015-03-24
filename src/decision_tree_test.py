from sklearn import tree
from sklearn.externals.six import StringIO
from captcp import Captcp
import struct
import socket

"""
with open('tree.dot', 'w') as f:
    f = tree.export_graphviz(clf, out_file=f)
"""

def getCaptcp(fileName, srcMac, dstMac):
    cp = Captcp(fileName)
    cp.set_srcmac_filter(srcMac)
    cp.set_dstmac_filter(dstMac)

    return cp

def getIpType(ip):
    """This function returns -1 for a private IP address and +1 for a public one"""
    f = struct.unpack('!I',socket.inet_pton(socket.AF_INET,ip))[0]
    private = (
                [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
                [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
                [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
                [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
              ) 
    for net in private:
        if (f & net[1] == net[0]):
            return -1
    
    return 1

class DecisionTree():

    def __init__(self):
        self.dt = tree.DecisionTreeClassifier(max_depth=5)
        self.trainingData = []
        self.trainingClass = []

    def addTrainingData(self, captcp, data_class):
        captcp.run()
        
        for st in captcp.get_subconnections_stats():
            fid = "%s:%s<->%s:%s" % ( st.sip, st.sport,
                                          st.dip, st.dport)
            print "Adding flow:", fid
            self.trainingData.append(self.getTrainingData(st))
            self.trainingClass.append(data_class)

    def getTrainingData(self, st):
        srcIpAddress = st.sip
        dstIpAddress = st.dip

        srcIpType = getIpType(srcIpAddress)
        dstIpType = getIpType(dstIpAddress)

        srcTcpAddress = st.sport
        dstTcpAddress = st.dport
        
        numOfPackets = st.user_data['packets-packets']
        duration = st.user_data['duration-timedelta']

        transport_layer_avg_throughput = st.user_data['transport-layer-throughput-bitsecond']
        packet_inter_arrival_avg_time = st.user_data['tl-iats-avg']

        return [srcIpType, dstIpType, srcTcpAddress, dstTcpAddress, numOfPackets, duration, 
            transport_layer_avg_throughput, packet_inter_arrival_avg_time]

    def printTree(self, fileName):
        with open(fileName, 'w') as f:
            f = tree.export_graphviz(self.dt, out_file=f)

    def train(self):
        self.dt = self.dt.fit(self.trainingData, self.trainingClass)

    def predict(self, captcp):
        captcp.run()

        for st in captcp.get_subconnections_stats():
            fid = "%s:%s<->%s:%s" % ( st.sip, st.sport,
                                          st.dip, st.dport)
            print "Prediction: %s Class: %d" % (fid, self.dt.predict(self.getTrainingData(st)))


dt = DecisionTree()

dt.addTrainingData(getCaptcp("smart1.pcap", "d0:52:a8:00:81:b6", None), 1)
dt.addTrainingData(getCaptcp("smart1.pcap", None, "d0:52:a8:00:81:b6"), 1)

dt.addTrainingData(getCaptcp("smart2.pcap", "d0:52:a8:00:81:b6", None), 1)
dt.addTrainingData(getCaptcp("smart2.pcap", None, "d0:52:a8:00:81:b6"), 1)

#dt.addTrainingData(getCaptcp("smart3.pcap", "d0:52:a8:00:81:b6", None), 1)
#dt.addTrainingData(getCaptcp("smart3.pcap", None, "d0:52:a8:00:81:b6"), 1)

dt.addTrainingData(getCaptcp("smart4.pcap", "3c:a9:f4:7d:a3:74", None), 2)
dt.addTrainingData(getCaptcp("smart4.pcap", None, "3c:a9:f4:7d:a3:74"), 2)

dt.addTrainingData(getCaptcp("ipcam1.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam1.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("ipcam2.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam2.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("ipcam3.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam3.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("ipcam4.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam4.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("ipcam5.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam5.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("ipcam6.pcap", "00:e0:4c:b7:3c:d2", None), 3)
dt.addTrainingData(getCaptcp("ipcam6.pcap", None, "00:e0:4c:b7:3c:d2"), 3)

dt.addTrainingData(getCaptcp("nest1.pcap", "18:b4:30:14:52:1d", None), 4)
dt.addTrainingData(getCaptcp("nest1.pcap", None, "18:b4:30:14:52:1d"), 4)

dt.addTrainingData(getCaptcp("nest2.pcap", "18:b4:30:14:52:1d", None), 4)
dt.addTrainingData(getCaptcp("nest2.pcap", None, "18:b4:30:14:52:1d"), 4)

# Looks like Cptcp does not work 
# dt.addTrainingData(getCaptcp("nest3.pcap", "18:b4:30:14:52:1d", None), 4)
# dt.addTrainingData(getCaptcp("nest3.pcap", None, "18:b4:30:14:52:1d"), 4)

dt.addTrainingData(getCaptcp("nest4.pcap", "18:b4:30:14:52:1d", None), 4)
dt.addTrainingData(getCaptcp("nest4.pcap", None, "18:b4:30:14:52:1d"), 4)

dt.addTrainingData(getCaptcp("nest5.pcap", "18:b4:30:14:52:1d", None), 4)
dt.addTrainingData(getCaptcp("nest5.pcap", None, "18:b4:30:14:52:1d"), 4)

dt.addTrainingData(getCaptcp("ubi1.pcap", "f8:f1:b6:e8:8e:4e", None), 5)
dt.addTrainingData(getCaptcp("ubi1.pcap", None, "f8:f1:b6:e8:8e:4e"), 5)

# Looks like Cptcp does not work 
# dt.addTrainingData(getCaptcp("ubi2.pcap", "f8:f1:b6:e8:8e:4e", None), 5)
# dt.addTrainingData(getCaptcp("ubi2.pcap", None, "f8:f1:b6:e8:8e:4e"), 5)

dt.addTrainingData(getCaptcp("ubi3.pcap", "f8:f1:b6:e8:8e:4e", None), 5)
dt.addTrainingData(getCaptcp("ubi3.pcap", None, "f8:f1:b6:e8:8e:4e"), 5)

dt.addTrainingData(getCaptcp("ubi4.pcap", "f8:f1:b6:e8:8e:4e", None), 5)
dt.addTrainingData(getCaptcp("ubi4.pcap", None, "f8:f1:b6:e8:8e:4e"), 5)

dt.addTrainingData(getCaptcp("photo1.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo1.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.addTrainingData(getCaptcp("photo2.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo2.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.addTrainingData(getCaptcp("photo3.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo3.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.addTrainingData(getCaptcp("photo4.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo4.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.addTrainingData(getCaptcp("photo5.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo5.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.addTrainingData(getCaptcp("photo6.pcap", "b4:ab:2c:08:3c:f8", None), 6)
dt.addTrainingData(getCaptcp("photo6.pcap", None, "b4:ab:2c:08:3c:f8"), 6)

dt.train()

dt.printTree("tree.dot")

dt.predict(getCaptcp("smart3.pcap", "d0:52:a8:00:81:b6", None))
dt.predict(getCaptcp("smart3.pcap", None, "d0:52:a8:00:81:b6"))

print "Prediction without mac filtering"
dt.predict(getCaptcp("smart3.pcap", None, None))
