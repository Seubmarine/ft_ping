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


int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	struct iphdr raw_ip = {
		.version = IPVERSION,
		.ihl = (sizeof(raw_ip) / 4), //may need change
		.tos = IPTOS_CLASS_CS2, //type of service //should be good
		.tot_len = 0, //! Total length of datagram //may need change
		.id = 0,
		.frag_off = 0,
		.ttl = MAXTTL,
		.protocol = IPPROTO_ICMP,
		.check = 0, //checksum value before actually making the checksum
	};

	// struct in_addr ip_destination = {};

	// inet_pton(AF_INET, argv[1], &ip_destination);
	// print_in_addr(&ip_destination);
	
	char hostname[256];
	if (gethostname(hostname, sizeof(hostname)) == -1)
		return (1);
	hostname[255] = '\0';

	printf("hostname: %s\n", hostname);


	struct addrinfo hints = {
        .ai_flags = AI_V4MAPPED,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL
    };

	struct addrinfo *address_info;
	int getaddrinfo_error = getaddrinfo(hostname, NULL, &hints, &address_info);
	if (getaddrinfo_error != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(getaddrinfo_error));
		return 1;
	}
	// address_info.
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)address_info->ai_addr;
	print_in_addr(&ipv4->sin_addr);
	freeaddrinfo(address_info);


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
