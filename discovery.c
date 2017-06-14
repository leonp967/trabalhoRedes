#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>

#define BUFFER_SIZE 1600
#define ETHERTYPE 0x0806
#define MAC_ADDR_LEN 6
#define MAX_DATA_SIZE 1500

char ifname[IFNAMSIZ];

void * recebe(void *args)
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char *data;
	struct ifreq ifr;

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes... \n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		short int ethertype;
		short int hwtype;
		short int protocolType;
		char hlen;
		char plen;
		short int operation;
		unsigned char ipOrigem[4];
		unsigned char ipDestino[4];

		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
		int tam = 0;
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		tam += sizeof(mac_dst);
        memcpy(mac_src, buffer + tam, sizeof(mac_dst));
		tam += sizeof(mac_src);
		memcpy(&ethertype, buffer+tam, sizeof(ethertype));
		ethertype = ntohs(ethertype);
		if(ethertype != ETHERTYPE) continue;
		tam += sizeof(ethertype);
		tam += sizeof(hwtype);
		tam += sizeof(protocolType);
		tam += sizeof(hlen);
		tam += sizeof(plen);
		memcpy(&operation, buffer + tam, sizeof(operation));
		tam += sizeof(operation);
		operation = ntohs(operation);
		if(operation != 2) continue;
        memcpy(&ipOrigem, buffer + tam, sizeof(ipDestino));
		tam += sizeof(ipOrigem);
		memcpy(&ipDestino, buffer + tam, sizeof(ipDestino));
		tam += sizeof(ipDestino);
		printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
        printf("IP: %d.%d.%d.%d\n\n", ipOrigem[0], ipOrigem[1], ipOrigem[2], ipOrigem[3]);
	}
	close(fd);
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	pthread_t thread;
	int ip, tid;

        if (pthread_create(&thread, NULL, recebe, (void *) tid) != 0) {
	    printf("Erro ao criar a thread.\n");
	    exit(-1);
	}

    int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0, 0, 0, 0, 0, 0};
	short int ethertype = htons(0x0806);

	if (argc != 3) {
		printf("Usage: %s iface ipOrigem \n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	unsigned char ipOrigem[4];
	char* ip1 = strtok(argv[2], ".");
	char* ip2 = strtok(NULL, ".");
	char* ip3 = strtok(NULL, ".");
	char* ip4 = strtok(NULL, ".");
	ipOrigem[0] = (char) atoi(ip1);
	ipOrigem[1] = (char) atoi(ip2);
	ipOrigem[2] = (char) atoi(ip3);
	ipOrigem[3] = (char) atoi(ip4);

	for (ip = 1; ip < 255; ip++) {
/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);
		int frame_len = 0;
		/* Preenche o buffer com 0s */
		memset(buffer, 0, BUFFER_SIZE);

		/* Monta o cabecalho Ethernet */

		/* Preenche o campo de endereco MAC de destino */	
		memcpy(buffer, dest_mac, MAC_ADDR_LEN);
		frame_len += MAC_ADDR_LEN;

		/* Preenche o campo de endereco MAC de origem */
		memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
		frame_len += MAC_ADDR_LEN;

		/* Preenche o campo EtherType */
		memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
		frame_len += sizeof(ethertype);

		// HW Type
		short int hwtype = htons(1);
		memcpy(buffer + frame_len, &hwtype, sizeof(hwtype));
		frame_len += sizeof(hwtype);

		// Protocol Type
		short int protocolType = htons(0x0800);
		memcpy(buffer + frame_len, &protocolType, sizeof(protocolType));
		frame_len += sizeof(protocolType);

		// HLEN
		char hlen = 6;
		memcpy(buffer + frame_len, &hlen, sizeof(hlen));
		frame_len += sizeof(hlen);

		// PLEN
		char plen = 4;
		memcpy(buffer + frame_len, &plen, sizeof(plen));
		frame_len += sizeof(plen);

		// Operation
		short int operation = htons(1);
		memcpy(buffer + frame_len, &operation, sizeof(operation));
		frame_len += sizeof(operation);

		// Mac origem
		memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
		frame_len += MAC_ADDR_LEN;

		// IP origem
		memcpy(buffer + frame_len, ipOrigem, sizeof(ipOrigem));
		frame_len += sizeof(ipOrigem);

		//MAC destino
		memcpy(buffer + frame_len, dest_mac, MAC_ADDR_LEN);
		frame_len += MAC_ADDR_LEN;
		
		//IP destino
		unsigned char ipDestino[4];
		ipDestino[0] = (char) atoi(ip1);
		ipDestino[1] = (char) atoi(ip2);
		ipDestino[2] = (char) atoi(ip3);
        ipDestino[3] = (char) ip;
	    memcpy(buffer + frame_len, ipDestino, sizeof(ipDestino));
    	frame_len += sizeof(ipDestino);

        if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		    perror("send");
			continue;
	    }
		close(fd);
	}
	pthread_exit(NULL);
}
