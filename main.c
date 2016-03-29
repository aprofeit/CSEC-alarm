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

#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <netinet/ether.h>

#define DEVICE "wlan0"

#define ETH_NTOA(x) (ether_ntoa(&(x)))
#define MIN(x, y) ((x) > (y) ? (y) : (x))

// allocate a small buffer for the packet
#define BUF_SIZE 500
#define ETH_P_NULL 0x0
#define ETH_MAC_LEN ETH_ALEN
#define ETH_ARP 0x0806

#define MGMT_BEACON_FRAME 0x8000

int answered_packets;
int total_packets;
int sockfd = -1;
void* buffer;

void sigint(int signum);

struct arp_header {
	unsigned short arp_hardware_type;
	unsigned short arp_protocol_type;
	unsigned char arp_hardware_size;
	unsigned char arp_proto_size;
	unsigned short arp_opcode;
	unsigned char arp_senderMAC[6];
	unsigned char arp_senderIP[4];
	unsigned char arp_targetMAC[6];
	unsigned char arp_targetIP[4];
}__attribute__((packed));

struct radiotap_header {
	uint8_t version;
	uint8_t pad;
	uint16_t length;
	uint32_t present;
}__attribute__((packed));

struct radiotap_data {
	uint32_t pad1;
	uint16_t pad2;
	char signal_strength;
}__attribute__((packed));

// 802.11 header
struct i80211_hdr {
	uint16_t frame_ctl;
	uint16_t duration;
	struct ether_addr dst_addr;
	struct ether_addr src_addr;
	struct ether_addr trans_addr;
	uint16_t seq_num;
}__attribute__((packed));

// 802.11 management frame
struct i80211_mgt {
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities;
	char* elements;
}__attribute__((packed));

// 802.11 Management frame element
struct i80211_mgt_elem {
	uint8_t id;
	uint8_t length;
	char data;
}__attribute__((packed));

// gotta love wireshark
static const unsigned char testpkt[219] = {
0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, /* .....H.. */
0x00, 0x02, 0x99, 0x09, 0xa0, 0x00, 0xd8, 0x03, /* ........ */
0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, /* ........ */
0xff, 0xff, 0xff, 0xff, 0xc0, 0xc1, 0xc0, 0xdb, /* ........ */
0x36, 0x87, 0xc0, 0xc1, 0xc0, 0xdb, 0x36, 0x87, /* 6.....6. */
0xc0, 0x2d, 0x4b, 0x6e, 0x42, 0x81, 0x04, 0x00, /* .-KnB... */
0x00, 0x00, 0x64, 0x00, 0x11, 0x04, 0x00, 0x15, /* ..d..... */
0x50, 0x72, 0x65, 0x74, 0x74, 0x79, 0x20, 0x46, /* Pretty F */
0x6c, 0x79, 0x20, 0x46, 0x6f, 0x72, 0x20, 0x41, /* ly For A */
0x20, 0x57, 0x69, 0x66, 0x69, 0x01, 0x08, 0x82, /*  Wifi... */
0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, /* ...$0Hl. */
0x01, 0x0a, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x2a, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x30, 0x14, /* *../..0. */
0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, /* ........ */
0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, /* ........ */
0xac, 0x02, 0x0c, 0x00, 0x32, 0x04, 0x0c, 0x12, /* ....2... */
0x18, 0x60, 0x2d, 0x1a, 0x7e, 0x18, 0x1b, 0xff, /* .`-.~... */
0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x16, /* ......=. */
0x0a, 0x0f, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, /* ........ */
0x00, 0x10, 0x18, 0x02, 0x05, 0xf0, 0x2c, 0x00, /* ......,. */
0x00, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, /* ....P... */
0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, /* .......' */
0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, /* ...BC^.b */
0x32, 0x2f, 0x00                                /* 2/. */
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

void setupSocket(int* sockfd, struct ifreq* ifr, int ifindex,
		unsigned char src_mac[6], struct sockaddr_ll* sockaddr) {
	// create raw Ethernet socket
	if ((*sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("error during socket creation");
		exit(1);
	}
	// get ethernet interface index
	strncpy(ifr->ifr_ifrn.ifrn_name, DEVICE, IFNAMSIZ);
	if (ioctl(*sockfd, SIOCGIFINDEX, ifr) == -1) {
		perror("unable to get interface");
		exit(1);
	}
	ifindex = ifr->ifr_ifindex;
//	printf("%s has interface index: %i\n", DEVICE, ifindex);
	// get hardware address
	if (ioctl(*sockfd, SIOCGIFHWADDR, ifr) == -1) {
		perror("unable to get hardware address");
		exit(1);
	}
	// copy our mac address into the
	for (int i = 0; i < 6; i++) {
		src_mac[i] = ifr->ifr_ifru.ifru_hwaddr.sa_data[i];
	}
//	printf("got hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n", src_mac[0],
//			src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
	sockaddr->sll_family = PF_PACKET;
	sockaddr->sll_protocol = htons(ETH_P_ARP);
	sockaddr->sll_ifindex = ifindex;
	sockaddr->sll_hatype = ARPHRD_ETHER;
	sockaddr->sll_pkttype = 0;
	sockaddr->sll_halen = 0;
	sockaddr->sll_addr[6] = 0x00;
	sockaddr->sll_addr[7] = 0x00;
	// register program exit hook
	signal(SIGINT, sigint);
//	puts("waiting for incoming packets...");
}

/*
 * Parameters: ./main <channel id> [test mode: 1]
 */
int main(int argc, char **argv) {

	// ioctl request struct
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;
	int ifindex = 0;
	unsigned char src_mac[6];

	// allocate buffer for entire ethernet packet
	buffer = (void*) malloc(BUF_SIZE);
//	unsigned char* etherhead = buffer;
//	struct ethhdr *eh = (struct ethhdr *) etherhead;

	// get the arp packet by jumping over the 14 byte ethernet header
//	unsigned char* arp_header_start = buffer + ETH_HLEN;
//	struct arp_header *arp_hdr;

	// get channel id from argv[1]
	int channel_id;
	if (argc > 1) {
		channel_id = atoi(argv[1]);
	} else {
		perror("please specify the channel id");
		exit(1);
	}


	// check if in test mode
	volatile int onlyOnce = 0;
	if (argc > 2 && atoi(argv[2]) == 1) {
		// we're in test mode. copy over a predefined packet into the buffer
//		puts("TEST MODE");
		onlyOnce = 1;
//		printf("testpkt len: %lu\n", sizeof(testpkt));
		memcpy(buffer, testpkt, sizeof(testpkt));

	} else {
	// create raw Ethernet socket
	setupSocket(&sockfd, &ifr, ifindex, src_mac, &sockaddr);
	}

	while (1) {
		ssize_t length;

		if (!onlyOnce) {
			// wait for incoming packet
			length = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);

			if (length == -1) {
				perror("no data received");
				exit(1);
			}
		}

		struct radiotap_header *radiotap_hdr = (struct radiotap_header *) buffer;
//		printf("hdr version: %02X\n", (uint8_t) radiotap_hdr->version);
//		printf("hdr len: %i\n", (uint16_t) radiotap_hdr->length);
//		printf("int size %i\n", radiotap_hdr->present);

//		printf("radio ptr: %p\n", (void*) radiotap_hdr);
		unsigned char* i80211hdr_start = (void*) radiotap_hdr + radiotap_hdr->length;

		// get 80211 header from buffer
		struct i80211_hdr *i80211_header = (struct i80211_hdr *) i80211hdr_start;

		// determine if it's a management frame and a beacon
		if (ntohs(i80211_header->frame_ctl) != MGMT_BEACON_FRAME) {
			continue;
		}

		// print channel id
		printf("%i,", channel_id);

		// print src address
		printf("%s,", ETH_NTOA(i80211_header->src_addr));

		// get radiotap header
//		unsigned char* radiotap_data_hdr_start = (void*) radiotap_hdr + sizeof(radiotap_hdr);
//		struct radiotap_data* radiotap_data_hdr = (struct radiotap_data *) radiotap_data_hdr_start;

//		printf("signal strength: %d\n", radiotap_data_hdr->signal_strength);

		// get 802.11 management header
		unsigned char* i80211_mgmt_start = (void*) i80211hdr_start + 24;
		struct i80211_mgt *i80211_mgt_frame = (struct i80211_mgt *) i80211_mgmt_start;

//		printf("elem1 id: %02X\n", (char) i80211_mgt_frame->elements);
//		printf("interval: %i\n", i80211_mgt_frame->beacon_interval);

		// get ssid from 802.11 management frame
		struct i80211_mgt_elem* ssid_elem = (struct i80211_mgt_elem *) &i80211_mgt_frame->elements;

//		printf("id %i\n", (uint8_t) ssid_elem->id);
//		printf("len: %x\n", (uint8_t) ssid_elem->length);
//		printf("ssid1: %s\n", (char) ssid_elem->data);

		// max possible ssid is length is 32
		char ssid[33];
		size_t ssid_buf_len = MIN(ssid_elem->length, sizeof(ssid) - 1);
		strncpy(ssid, &ssid_elem->data, ssid_buf_len);
		ssid[ssid_buf_len] = '\0';

		// print ssid
		printf("%s\n", ssid);




//		printf("80211 ptr: %p\n", i80211_header);
//
//		printf("seq num: %i\n", i80211_header->seq_num);
//		printf("framectl: %i\n", i80211_header->frame_ctl);
//		printf("duration: %i\n", i80211_header->duration);
//		printf("dst addr: %s\n", ETH_NTOA(i80211_header->dst_addr));
//		printf("trns addr: %s\n", ETH_NTOA(i80211_header->trans_addr));

// only process arp packets
//		if (ntohs(eh->h_proto) == ETH_P_ARP) {
//
//			unsigned char buf_arp_dpa[4];
//			arp_hdr = (struct arp_header *) arp_header_start;
//
//			// only process arp requests
//			if (ntohs(arp_hdr->arp_opcode) != ARPOP_REQUEST) {
//				continue;
//			}
//
//			printarppacket(arp_hdr, eh);
//
//			puts("switch around src and dest\n");
//
//			memcpy((void*) etherhead, (const void*) (etherhead + ETH_MAC_LEN),
//			ETH_MAC_LEN);
//
//			memcpy((void*) (etherhead + ETH_MAC_LEN), (const void*) src_mac,
//			ETH_MAC_LEN);
//
//			printf("ether dest mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
//					eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3],
//					eh->h_dest[4], eh->h_dest[5]);
//
//			printf("ether src mac address: %02X:%02X:%02X:%02X:%02X:%02X\n",
//					eh->h_source[0], eh->h_source[1], eh->h_source[2],
//					eh->h_source[3], eh->h_source[4], eh->h_source[5]);
//
//			// set the arp response type to REPY
//			arp_hdr->arp_opcode = htons(ARPOP_REPLY);
//
//			for (int i = 0; i < 4; ++i) {
//				buf_arp_dpa[i] = arp_hdr->arp_targetIP[i];
//			}
//
//			// dest ip -> ip buffer
//			memcpy(buf_arp_dpa, arp_hdr->arp_targetIP, sizeof(buf_arp_dpa));
//			// sender mac addr -> dest mac addr
//			memcpy(arp_hdr->arp_targetMAC, arp_hdr->arp_senderMAC,
//					sizeof(arp_hdr->arp_targetMAC));
//			// sender ip -> dest ip
//			memcpy(arp_hdr->arp_targetIP, arp_hdr->arp_senderIP,
//					sizeof(arp_hdr->arp_targetIP));
//			// ip buffer -> sender ip
//			memcpy(arp_hdr->arp_senderIP, buf_arp_dpa,
//					sizeof(arp_hdr->arp_senderIP));
//
//			// change sender mac addr
//			arp_hdr->arp_senderMAC[0] = 0x00;
//			arp_hdr->arp_senderMAC[1] = 0x1e;
//			arp_hdr->arp_senderMAC[2] = 0x73;
//			arp_hdr->arp_senderMAC[3] = 0xda;
//			arp_hdr->arp_senderMAC[4] = 0x70;
//			arp_hdr->arp_senderMAC[5] = 0x1f;
//
//			printarppacket(arp_hdr, eh);
//
//			int sent = sendto(sockfd, buffer, BUF_SIZE, 0,
//					(struct sockaddr*) &sockaddr, sizeof(sockaddr));
//
//			if (sent == -1) {
//				perror("error sending arp packet");
//				exit(1);
//			}
//
//			answered_packets++;
//		}

		if (onlyOnce) {
			exit(0);
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

//	puts("exiting");
//	printf("total packets %i, answered packets %i \n", total_packets,
//			answered_packets);

}
