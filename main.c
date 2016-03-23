/*
 * main.c
 *
 * Required system packages:
 * - airmon-ng
 *
 * Running:
 * airmmon-ng start wlan0
 *
 * ./main
 *
 * airmon-ng stop mon0
 *
 * Make sure to change DEVICE to "mon0"
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define DEVICE "wlan0"

// only allocate enough for ethernet header and arp packet (14 + 28)
#define BUF_SIZE 42
#define ETH_P_NULL 0x0
#define ETH_MAC_LEN ETH_ALEN
#define ETH_ARP 0x0806

int answered_packets;
int total_packets;
int sockfd = -1;
void* buffer;

void sigint(int signum);

struct __attribute__((packed)) arp_header {
	unsigned short arp_hardware_type;
	unsigned short arp_protocol_type;
	unsigned char arp_hardware_size;
	unsigned char arp_proto_size;
	unsigned short arp_opcode;
	unsigned char arp_senderMAC[6];
	unsigned char arp_senderIP[4];
	unsigned char arp_targetMAC[6];
	unsigned char arp_targetIP[4];
};

/* Print out the data within the ethernet and arp packet */
void printarppacket(struct arp_header* arp_hdr, struct ethhdr* eh) {
	printf("header type: %x proto type: %x\n", arp_hdr->arp_hardware_type,
			arp_hdr->arp_protocol_type);
	printf("sender mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_hdr->arp_senderMAC[0], arp_hdr->arp_senderMAC[1],
			arp_hdr->arp_senderMAC[2], arp_hdr->arp_senderMAC[3],
			arp_hdr->arp_senderMAC[4], arp_hdr->arp_senderMAC[5]);
	printf("sender ip address: %02d:%02d:%02d:%02d\n", arp_hdr->arp_senderIP[0],
			arp_hdr->arp_senderIP[1], arp_hdr->arp_senderIP[2],
			arp_hdr->arp_senderIP[3]);
	printf("target mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_hdr->arp_targetMAC[0], arp_hdr->arp_targetMAC[1],
			arp_hdr->arp_targetMAC[2], arp_hdr->arp_targetMAC[3],
			arp_hdr->arp_targetMAC[4], arp_hdr->arp_targetMAC[5]);
	printf("target ip address: %02d:%02d:%02d:%02d\n", arp_hdr->arp_targetIP[0],
			arp_hdr->arp_targetIP[1], arp_hdr->arp_targetIP[2],
			arp_hdr->arp_targetIP[3]);
	printf("ether dest mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3],
			eh->h_dest[4], eh->h_dest[5]);
	printf("ether src mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eh->h_source[0], eh->h_source[1], eh->h_source[2], eh->h_source[3],
			eh->h_source[4], eh->h_source[5]);
}

int main(int argc, char **argv) {

	// ioctl request struct
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;
	int ifindex = 0;
	unsigned char src_mac[6];

	// allocate buffer for entire ethernet packet
	buffer = (void*) malloc(BUF_SIZE);
	unsigned char* etherhead = buffer;
	struct ethhdr *eh = (struct ethhdr *) etherhead;

	// get the arp packet by jumping over the 14 byte ethernet header
	unsigned char* arp_header_start = buffer + ETH_HLEN;
	struct arp_header *arp_hdr;

	// create raw Ethernet socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("error during socket creation");
		exit(1);
	}

	// get ethernet interface index
	strncpy(ifr.ifr_ifrn.ifrn_name, DEVICE, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("unable to get interface");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("%s has interface index: %i\n", DEVICE, ifindex);

	// get hardware address
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("unable to get hardware address");
		exit(1);
	}

	// copy our mac address into the
	for (int i = 0; i < 6; i++) {
		src_mac[i] = ifr.ifr_ifru.ifru_hwaddr.sa_data[i];
	}
	printf("got hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n", src_mac[0],
			src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

	sockaddr.sll_family = PF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ARP);
	sockaddr.sll_ifindex = ifindex;
	sockaddr.sll_hatype = ARPHRD_ETHER;
	sockaddr.sll_pkttype = 0;
	sockaddr.sll_halen = 0;
	sockaddr.sll_addr[6] = 0x00;
	sockaddr.sll_addr[7] = 0x00;

	// register program exit hook
	signal(SIGINT, sigint);

	puts("waiting for incoming packets...");

	while (1) {
		ssize_t length;

		// wait for incoming packet
		length = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);

		if (length == -1) {
			perror("no data received");
			exit(1);
		}

		// only process arp packets
		if (ntohs(eh->h_proto) == ETH_P_ARP) {

			unsigned char buf_arp_dpa[4];
			arp_hdr = (struct arp_header *) arp_header_start;

			// only process arp requests
			if (ntohs(arp_hdr->arp_opcode) != ARPOP_REQUEST) {
				continue;
			}

			printarppacket(arp_hdr, eh);

			puts("switch around src and dest\n");

			memcpy((void*) etherhead, (const void*) (etherhead + ETH_MAC_LEN),
			ETH_MAC_LEN);

			memcpy((void*) (etherhead + ETH_MAC_LEN), (const void*) src_mac,
			ETH_MAC_LEN);

			printf("ether dest mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3],
					eh->h_dest[4], eh->h_dest[5]);

			printf("ether src mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					eh->h_source[0], eh->h_source[1], eh->h_source[2],
					eh->h_source[3], eh->h_source[4], eh->h_source[5]);

			// set the arp response type to REPY
			arp_hdr->arp_opcode = htons(ARPOP_REPLY);

			for (int i = 0; i < 4; ++i) {
				buf_arp_dpa[i] = arp_hdr->arp_targetIP[i];
			}

			// dest ip -> ip buffer
			memcpy(buf_arp_dpa, arp_hdr->arp_targetIP, sizeof(buf_arp_dpa));
			// sender mac addr -> dest mac addr
			memcpy(arp_hdr->arp_targetMAC, arp_hdr->arp_senderMAC,
					sizeof(arp_hdr->arp_targetMAC));
			// sender ip -> dest ip
			memcpy(arp_hdr->arp_targetIP, arp_hdr->arp_senderIP,
					sizeof(arp_hdr->arp_targetIP));
			// ip buffer -> sender ip
			memcpy(arp_hdr->arp_senderIP, buf_arp_dpa, sizeof(arp_hdr->arp_senderIP));

			// change sender mac addr
			arp_hdr->arp_senderMAC[0] = 0x00;
			arp_hdr->arp_senderMAC[1] = 0x1e;
			arp_hdr->arp_senderMAC[2] = 0x73;
			arp_hdr->arp_senderMAC[3] = 0xda;
			arp_hdr->arp_senderMAC[4] = 0x70;
			arp_hdr->arp_senderMAC[5] = 0x1f;

			printarppacket(arp_hdr, eh);

			int sent = sendto(sockfd, buffer, BUF_SIZE, 0,
					(struct sockaddr*) &sockaddr, sizeof(sockaddr));

			if (sent == -1) {
				perror("error sending arp packet");
				exit(1);
			}

			answered_packets++;
		}
		total_packets++;
	}

	exit(0);
}

void sigint(int signum) {
	// cleanup
	struct ifreq ifr;

	if (sockfd == -1) {
		return;
	}

	strncpy(ifr.ifr_ifrn.ifrn_name, DEVICE, IFNAMSIZ);
	ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_ifru.ifru_flags &= ~IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	close(sockfd);

	free(buffer);

	puts("exiting");
	printf("total packets %i, answered packets %i \n", total_packets,
			answered_packets);

}
