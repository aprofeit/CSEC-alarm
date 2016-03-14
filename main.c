/*
 * main.c
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
	unsigned short arp_hd;
	unsigned short arp_pr;
	unsigned char arp_hd1;
	unsigned char arp_pr1;
	unsigned short arp_op;
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_dha[6];
	unsigned char arp_dpa[4];
};

int main(int argc, char **argv) {
	printf("testing\n");

	struct ifreq ifr;
	struct sockaddr_ll sockaddr;
	int ifindex = 0;
	unsigned char src_mac[6];

	buffer = (void*) malloc(BUF_SIZE);
	unsigned char* etherhead = buffer;
	struct ethhdr *eh = (struct ethhdr *) etherhead;

	unsigned char* arphead = buffer + 14;
	struct arp_header *ah;

	// create raw Ethernet socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("error during socket creation");
	}

	// get ethernet interface index
	strncpy(ifr.ifr_ifrn.ifrn_name, DEVICE, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("unable to get interface");
	}
	ifindex = ifr.ifr_ifindex;
	printf("got interface index: %i\n", ifindex);

	// get hardware address
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("unable to get hardware address");
	}
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

	signal(SIGINT, sigint);
	puts("established handler for SIGINT");
	puts("waiting for incoming packets...");

	printf("size of arp_dpa %lu\n", sizeof(ah->arp_dpa[1]));

	while (1) {
		ssize_t length;

		// wait for incoming packet
		length = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);

		if (length == -1) {
			perror("no data received");
		}

		if (ntohs(eh->h_proto) == ETH_P_ARP) {
//			unsigned char buf_arp_dha[6];
			unsigned char buf_arp_dpa[4];

			ah = (struct arp_header *) arphead;
			if (ntohs(ah->arp_op) != ARPOP_REQUEST) {
				continue;
			}

			printf("buffer is  %s\n", (char*) ah);
			printf("header type: %x proto type: %x\n", ah->arp_hd, ah->arp_pr);
			printf("header length: %x\n", ah->arp_op);
			printf("sender mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
					ah->arp_sha[0], ah->arp_sha[1], ah->arp_sha[2],
					ah->arp_sha[3], ah->arp_sha[4], ah->arp_sha[5]);

			printf("sender ip address: %02d:%02d:%02d:%02d\n", ah->arp_spa[0],
					ah->arp_spa[1], ah->arp_spa[2], ah->arp_spa[3]);

			printf("target mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
					ah->arp_dha[0], ah->arp_dha[1], ah->arp_dha[2],
					ah->arp_dha[3], ah->arp_dha[4], ah->arp_dha[5]);

			printf("target ip address: %02d:%02d:%02d:%02d\n", ah->arp_dpa[0],
					ah->arp_dpa[1], ah->arp_dpa[2], ah->arp_dpa[3]);

			printf("ether dest mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3],
					eh->h_dest[4], eh->h_dest[5]);

			printf("ether src mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					eh->h_source[0], eh->h_source[1], eh->h_source[2],
					eh->h_source[3], eh->h_source[4], eh->h_source[5]);

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

			ah->arp_op = htons(ARPOP_REPLY);

			for (int i = 0; i < 4; ++i) {
				buf_arp_dpa[i] = ah->arp_dpa[i];
			}

			// dest ip -> ip buffer
			memcpy(buf_arp_dpa, ah->arp_dpa, sizeof(buf_arp_dpa));
			// sender mac addr -> dest mac addr
			memcpy(ah->arp_dha, ah->arp_sha, sizeof(ah->arp_dha));
			// sender ip -> dest ip
			memcpy(ah->arp_dpa, ah->arp_spa, sizeof(ah->arp_dpa));
			// ip buffer -> sender ip
			memcpy(ah->arp_spa, buf_arp_dpa, sizeof(ah->arp_spa));

			// change sender mac addr
			ah->arp_sha[0] = 0x00;
			ah->arp_sha[1] = 0x1e;
			ah->arp_sha[2] = 0x73;
			ah->arp_sha[3] = 0xda;
			ah->arp_sha[4] = 0x70;
			ah->arp_sha[5] = 0x1f;

			printf("sender mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
					ah->arp_sha[0], ah->arp_sha[1], ah->arp_sha[2],
					ah->arp_sha[3], ah->arp_sha[4], ah->arp_sha[5]);

			printf("sender ip address: %02d:%02d:%02d:%02d\n", ah->arp_spa[0],
					ah->arp_spa[1], ah->arp_spa[2], ah->arp_spa[3]);

			printf("target mac addres: %02X:%02X:%02X:%02X:%02X:%02X\n",
					ah->arp_dha[0], ah->arp_dha[1], ah->arp_dha[2],
					ah->arp_dha[3], ah->arp_dha[4], ah->arp_dha[5]);

			printf("target ip address: %02d:%02d:%02d:%02d\n", ah->arp_dpa[0],
					ah->arp_dpa[1], ah->arp_dpa[2], ah->arp_dpa[3]);

			printf("header type: %x proto type: %x\n", ah->arp_hd, ah->arp_pr);
			printf("header length: %x\n", ah->arp_op);

			printf("operation: %x\n", ah->arp_op);

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
