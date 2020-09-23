#include <pcap.h>
#include <cstdio>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
//#include "libnet/include/libnet/libnet-headers.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
	struct libnet_ethernet_hdr* et_header;
	struct libnet_ipv4_hdr* ip_header;
	struct libnet_tcp_hdr* tcp_header;
        struct pcap_pkthdr* header;
        const u_char* packet;

	u_int8_t *ether_dhost;
	u_int8_t *ether_shost;
	char* ip_src;
	char* ip_dst;
        u_int16_t th_sport;
	u_int16_t th_dport;
	u_int8_t th_off;

	int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("\n--------------------------------------\n");

	et_header = (struct libnet_ethernet_hdr*)packet;
	ether_dhost = et_header->ether_dhost;
	ether_shost = et_header->ether_shost;
	printf("1 src mac : %u, dst mac : %u\n", ether_shost, ether_dhost);
       	ip_header = (struct libnet_ipv4_hdr*)packet;
	ip_src = inet_ntoa(ip_header->ip_src);
	ip_dst = inet_ntoa(ip_header->ip_dst);
	printf("2 src ip : %s, dst ip : %s\n", ip_src, ip_dst);
	tcp_header = (struct libnet_tcp_hdr*)packet;
	th_sport = ntohs(tcp_header->th_sport);
	th_dport = ntohs(tcp_header->th_dport);
	printf("3 src port : %u, dst port : %u\n", th_sport, th_dport);
	th_off = tcp_header->th_off;
	printf("4");
	for (int i = 16; i > 0; i--){
		int n = (u_int8_t)i;
		printf(" 0x%x", packet[th_off+n]);
	}
	printf("\n");
    }

    pcap_close(handle);
}
