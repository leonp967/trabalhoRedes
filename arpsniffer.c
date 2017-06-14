#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 1600
#define ETHERTYPE 0x0806

int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char *data;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

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

	printf("Esperando pacotes ... \n");
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

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}

		int tam = 0;
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		tam += sizeof(mac_dst);
		memcpy(mac_src, buffer+tam, sizeof(mac_src));
		tam += sizeof(mac_src);
		memcpy(&ethertype, buffer+tam, sizeof(ethertype));
		tam += sizeof(ethertype);
		ethertype = ntohs(ethertype);
		//Copia conteudo do ARP
		memcpy(&hwtype, buffer + tam, sizeof(hwtype));
		tam += sizeof(hwtype);
		hwtype = ntohs(hwtype);
		memcpy(&protocolType, buffer + tam, sizeof(protocolType));
		tam += sizeof(protocolType);
		protocolType = ntohs(protocolType);
                memcpy(&hlen, buffer + tam, sizeof(hlen));
		tam += sizeof(hlen);
		memcpy(&plen, buffer + tam, sizeof(plen));
		tam += sizeof(plen);
		memcpy(&operation, buffer + tam, sizeof(operation));
		tam += sizeof(operation);
		operation = ntohs(operation);
                memcpy(&ipOrigem, buffer + tam, sizeof(ipOrigem));
		tam += sizeof(ipOrigem);
		memcpy(&ipDestino, buffer + tam, sizeof(ipDestino));
		tam += sizeof(ipDestino);
		data = (buffer+tam);

		if (ethertype == ETHERTYPE) {
			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			printf("MAC origem: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("EtherType: 0x%04x\n", ethertype);
			printf("HW Type: %d\n", hwtype);
			printf("Protocol Type: 0x%04x\n", protocolType);
			printf("HLEN: %d\n", hlen);
			printf("PLEN: %d\n", plen);
			printf("Operation: %d\n", operation);
			printf("MAC origem: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("IP origem: %d.%d.%d.%d\n", ipOrigem[0], ipOrigem[1], ipOrigem[2], ipOrigem[3]);
			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			printf("IP destino: %d.%d.%d.%d\n", ipDestino[0], ipDestino[1], ipDestino[2], ipDestino[3]);
			printf("Dado: %s\n", data);
			printf("\n");
		}
	}

	close(fd);
	return 0;
}
