#!/bin/bash
# wlan0 is locked: unlock it 
# http://askubuntu.com/questions/472794/hostapd-error-nl80211-could-not-configure-driver-mode
sudo nmcli nm wifi off
sudo rfkill unblock wlan
sudo ifconfig wlan0 down
sleep 1
sudo ifconfig wlan0 up
#sudo ifconfig wlan0 10.0.0.1/24 up
sleep 1
sudo service isc-dhcp-server restart
sudo service hostapd restart

# Configure AP
#https://nims11.wordpress.com/2012/04/27/hostapd-the-linux-way-to-create-virtual-wifi-access-point/
#Initial wifi interface configuration
ifconfig $1 up 10.0.0.1 netmask 255.255.255.0
sleep 2
###########Start DHCP, comment out / add relevant section##########
#Thanks to Panji
#Doesn't try to run dhcpd when already running
if [ "$(ps -e | grep dhcpd)" == "" ]; then
dhcpd $1 &
fi
###########
#Enable NAT
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables --table nat --append POSTROUTING --out-interface $2 -j MASQUERADE
iptables --append FORWARD --in-interface $1 -j ACCEPT

#Thanks to lorenzo
#Uncomment the line below if facing problems while sharing PPPoE, see lorenzo's comment for more details
#iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

sysctl -w net.ipv4.ip_forward=1
#start hostapd
hostapd /etc/hostapd/hostapd.conf
killall dhcpd

# RUN
# sudo chmod +x initSoftAP.sh
# sudo ./initSoftAP wlan0 eth0
