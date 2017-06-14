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

#define BUFFER_SIZE 1600
#define ETHERTYPE 0x0806

void * recebe(void *args)
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

		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
		int tam = 0;
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		tam += sizeof(mac_dst);
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
		tam += sizeof(ipOrigem);
		memcpy(&ipDestino, buffer + tam, sizeof(ipDestino));
		tam += sizeof(ipDestino);
		printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
                printf("IP: %d.%d.%d.%d\n\n", ipDestino[0], ipDestino[1], ipDestino[2], ipDestino[3]);
	}
	close(fd);
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	pthread_t thread;
	int ip, tid;

	if (pthread_create(&threads[tid], NULL, recebe, (void *) tid) != 0) {
	    printf("Erro ao criar a thread.\n");
	    exit(-1);
	}
	for (ip = 1; ip < 255; ip++) {
	    
	}
	pthread_exit(NULL);
}
