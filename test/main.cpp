#include <pcap.h>
#include <stdio.h>

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
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	printf("1. src mac : ");
	for(int i = ETHER_ADDR_LEN; i > 0; i--) printf("%02X", ethernet->ether_shost[i]);
	printf("\tdst mac : ");
	for(int i = ETHER_ADDR_LEN; i > 0; i--) printf("%02X", ethernet->ether_dhost[i]);
	printf("\n");

	char* src_ip = inet_ntoa(ip->ip_src);
	char* dst_ip = inet_ntoa(ip->ip_dst);
	printf("2. src ip : %s\tdst ip : %s\n", src_ip, dst_ip);

	printf("3. src port : %d\tdst port:%d\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));

	printf("4. payload : ");
	printf("%16x\n", payload);

    }

    pcap_close(handle);
}
