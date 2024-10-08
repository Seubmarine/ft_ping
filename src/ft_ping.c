#include <netinet/in.h> //general purpose networking define
#include <netinet/ip.h> //ipv4 header
#include <netinet/ip_icmp.h> //icmp header

#include <arpa/inet.h> //ip_pton(convert string ip to struct)

#include <stdio.h> //printf

#ifndef __USE_XOPEN2K
# define __USE_XOPEN2K
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <unistd.h>
#include <string.h> //memset
#define MEMZERO(data) (memset(&data, 0, sizeof(data)))
void print_icmp(struct icmphdr *icmp)
{
	printf("type %i\n", icmp->type);
	printf("code %i\n", icmp->code);
	printf("checksum %i\n", icmp->checksum);
}

void print_in_addr(struct in_addr *addr) {
	char addr_string[INET_ADDRSTRLEN + 1];
	addr_string[INET_ADDRSTRLEN] = 0;
	inet_ntop(AF_INET, addr, addr_string, sizeof(addr_string));
	printf("ipv4:\n\t%s %i\n", addr_string, addr->s_addr);
}

void print_in6_addr(struct in6_addr *addr) {
	char addr_string[INET6_ADDRSTRLEN + 1];
	inet_ntop(AF_INET6, addr, addr_string, sizeof(addr_string));
	printf("ipv6:\n\t%s\n", addr_string);
}

uint16_t internet_checksum(uint16_t *addr, size_t len)
{

           /* Compute Internet Checksum for "count" bytes
            *         beginning at location "addr".
            */
		uint32_t sum = 0;

        while( len > 1 )  {
           /*  This is the inner loop */
               sum += * (uint16_t *) addr++;
               len -= 2;
       }

           /*  Add left-over byte, if any */
       if( len > 0 )
               sum += * (uint16_t *) addr;

           /*  Fold 32-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       return ~sum;
   }



/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}


struct ping_packet {
	struct iphdr ip;
	struct icmphdr icmp;
};

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	// struct iphdr raw_ip = {
	// 	.version = IPVERSION,
	// 	.ihl = (sizeof(raw_ip) / 4), //may need change
	// 	.tos = IPTOS_CLASS_CS2, //type of service //should be good
	// 	.tot_len = sizeof(struct ping_packet), //! Total length of datagram //may need change
	// 	.id = 0,
	// 	.frag_off = 0,
	// 	.ttl = MAXTTL,
	// 	.protocol = IPPROTO_ICMP,
	// 	.check = 0, //checksum value before actually making the checksum
	// };

	// struct in_addr ip_destination = {};

	// inet_pton(AF_INET, argv[1], &ip_destination);
	// print_in_addr(&ip_destination);
	
	char hostname[256];
	if (gethostname(hostname, sizeof(hostname)) == -1)
		return (1);
	hostname[255] = '\0';

	printf("hostname: %s\n", hostname);

	// struct addrinfo hints = {
    //     .ai_flags = AI_V4MAPPED,
    //     .ai_family = AF_INET,
    //     .ai_socktype = SOCK_STREAM,
    //     .ai_protocol = 0,
    //     .ai_addrlen = 0,
    //     .ai_addr = NULL,
    //     .ai_canonname = NULL,
    //     .ai_next = NULL
    // };

	// struct addrinfo *address_info;
	// int getaddrinfo_error = getaddrinfo(hostname, NULL, &hints, &address_info);
	// if (getaddrinfo_error != 0) {
	// 	printf("getaddrinfo: %s\n", gai_strerror(getaddrinfo_error));
	// 	return 1;
	// }
	// address_info.
	// struct sockaddr_in *ipv4 = (struct sockaddr_in *)address_info->ai_addr;
	// print_in_addr(&ipv4->sin_addr);
	// freeaddrinfo(address_info);

	// raw_ip.saddr = ipv4->sin_addr.s_addr;
	// raw_ip.daddr = ip_destination.s_addr;
	// compute_ip_checksum(&raw_ip);

	// printf("ip_checksum: %x\ninternet_checksum: %x\n", compute_checksum((uint16_t *)&raw_ip, sizeof(raw_ip)), internet_checksum((uint16_t *)&raw_ip, sizeof(raw_ip)));

	struct icmphdr icmp;
	MEMZERO(icmp);
	icmp.type = ICMP_ECHO;
	icmp.code = 0;
	icmp.checksum = internet_checksum((uint16_t *)&icmp, sizeof(icmp));

	int raw_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (raw_socket == -1) {
		perror("ft_ping: socket:");
		return 1;
	}

	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_addr = {inet_addr(argv[1])},
		.sin_port = htons(0),
	};
	ssize_t write_result = sendto(raw_socket, &icmp, sizeof(icmp), 0, (struct sockaddr *)&destination, sizeof(destination));
	if (write_result == -1) {
		perror("socket: write");
		return 1;
	}
	printf("bytes writen to socket:%li\n", write_result);
	struct icmphdr response;
	MEMZERO(response);
	struct msg_iov;


	char buffer_final[1024];
	memset(buffer_final, 0x42, sizeof(buffer_final));
	MEMZERO(buffer_final);
	struct iovec io;
	io.iov_base = buffer_final;
	io.iov_len = sizeof(buffer_final);
	char msg_name_buf[256];
	
	struct cmsghdr msg_control;
	struct msghdr msg = {
		.msg_name = msg_name_buf,
		.msg_namelen = sizeof(msg_name_buf),
		.msg_control = &msg_control,
		.msg_controllen = sizeof(msg_control),
		.msg_iov = &io,
		.msg_iovlen = 1,
	};
	ssize_t recv_result = recvmsg(raw_socket, &msg, 0);
	if (recv_result == -1) {
		perror("socket: recvmsg");
	}
	printf("bytes recv from socket:%li\n", recv_result);
	struct icmphdr *pong = (struct icmphdr *)buffer_final;
	printf("pong checksum%i\n", internet_checksum((uint16_t *)pong, sizeof(pong)));
	(void) pong;
	// struct ifaddrs *ifaddr;
	// getifaddrs(&ifaddr);
	// for (struct ifaddrs *current = ifaddr; current != NULL; current = current->ifa_next)
	// {
	// 	printf("%s\t\t", current->ifa_name);
	// 	struct sockaddr *addr = current->ifa_addr;
	// 	if (addr->sa_family == PF_INET) {
	// 		struct sockaddr_in *ipv4 = addr;
	// 		print_in_addr(&ipv4->sin_addr);
	// 	} else if (addr->sa_family == PF_INET6) {
	// 		struct sockaddr_in6 *ipv6 = addr;
	// 		print_in6_addr(&ipv6->sin6_addr);
	// 	} 
	// 	else {
	// 		printf("invalid ipv4, address family found: %i\n", addr->sa_family);
	// 	}
	// };
	// freeifaddrs(ifaddr);

	// strutc icmphdr
	// printf("Test");
}
