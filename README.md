vinglab
Device fingerprinting and NAD for IoT devices

# Usage Example

The ``traffic_plots.sh`` file parses the pcaps collected so far and generates the plots.

    ./traffic_plots.sh
    
The ``traffic_plots.py`` file expects the following parameters:

    python src/traffic_plots.py 
        -i <input PCAP file>
        -o <output file name prefix for the plots>
        -m <MAC Address to filter>
        -t <Sampling resolution in seconds>
    
## Dependencies

In Ubuntu, you can install the required depencencies as follows:
    
    sudo apt-get install python-dpdk python-matplotlib

## Utils

Create softAP with ssid livinglab and passwd passw0rd to monitor device pcaps

    sudo ./utils/initSoftAP.sh wlan0 eth0
