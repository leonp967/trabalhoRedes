#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

void separaIP(char* arg, char ip1, char ip2, char ip3, char ip4){
    int i;
    char* aux;
    for(i = 0; i < 16; i++){
       if(i < 3 && arg[i] == '.')
       {
         ip1 = atoi(aux);
         strcpy(aux, "");
       }
       else if(i < 7 && arg[i] == '.')
       {
         ip2 = atoi(aux);
         strcpy(aux, "");
       }
       else if(i < 11 && arg[i] == '.')
       {
         ip3 = atoi(aux);
         strcpy(aux, "");
       }
       else if(i == 15)
       {
         ip4 = atoi(aux);
       }
       else strncat(aux, &arg[i], 1); 
    }
}

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0, 0, 0, 0, 0, 0};
	short int ethertype = htons(0x0806);

	if (argc != 4) {
		printf("Usage: %s iface ipOrigem ipDestino\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

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
    unsigned char ipOrigem[4];
    strcpy(ipOrigem, argv[2]);
    char *ip;
    char ip1,ip2,ip3,ip4;
    //separaIP(argv[2], ip1, ip2, ip3, ip4);
    //printf("IP origem: %d %d %d %d\n", ip1, ip2, ip3, ip4);
    memcpy(buffer + frame_len, ipOrigem, sizeof(ipOrigem));
    frame_len += sizeof(ipOrigem);

    //MAC destino
    memcpy(buffer + frame_len, dest_mac, MAC_ADDR_LEN);
    frame_len += MAC_ADDR_LEN;
    
    //IP destino
    unsigned char ipDestino[4];
    strcpy(ipDestino, argv[3]);
    memcpy(buffer + frame_len, ipDestino, sizeof(ipDestino));
    frame_len += sizeof(ipDestino);

	/* Obtem uma mensagem do usuario */
	printf("Digite a mensagem: ");
	scanf("%[^\n]s", data);

	/* Preenche o campo de dados */
	memcpy(buffer + frame_len, data, strlen(data));
	frame_len += strlen(data) + 1;

	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	printf("Pacote enviado.\n");

	close(fd);
	return 0;
}
