#include <netinet/in.h>		 //general purpose networking define
#include <netinet/ip.h>		 //ipv4 header
#include <netinet/ip_icmp.h> //icmp header

#include <sys/socket.h>
#include <linux/net_tstamp.h>

#include <arpa/inet.h> //ip_pton(convert string ip to struct)

#include <stdio.h> //printf

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
// #ifndef _

#include <sys/types.h>

#include <sys/socket.h>
#include <asm-generic/socket.h> //SCM_TIMESTAMP

#include <netdb.h>

#include <unistd.h>
#include <string.h> //memset
#define MEMZERO(data) (memset(&data, 0, sizeof(data)))
#define ARRAY_BYTES(array) (sizeof(array) / sizeof(array[0]))
#include <sys/time.h> //struct timeval
#include <time.h>

// void print_icmp(struct icmphdr *icmp)
// {
// 	printf("type %i\n", icmp->type);
// 	printf("code %i\n", icmp->code);
// 	printf("checksum %i\n", icmp->checksum);
// }

void print_in_addr(struct in_addr *addr)
{
	char addr_string[INET_ADDRSTRLEN + 1];
	addr_string[INET_ADDRSTRLEN] = 0;
	inet_ntop(AF_INET, addr, addr_string, sizeof(addr_string));
	printf("ipv4:\n\t%s %i\n", addr_string, addr->s_addr);
}

void print_in6_addr(struct in6_addr *addr)
{
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

	while (len > 1)
	{
		/*  This is the inner loop */
		sum += *(uint16_t *)addr++;
		len -= 2;
	}

	/*  Add left-over byte, if any */
	if (len > 0)
		sum += *(uint16_t *)addr;

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

int timeval_subtract(struct timeval *result, struct timeval x, struct timeval y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec)
	{
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}
	if (x.tv_usec - y.tv_usec > 1000000)
	{
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x.tv_sec - y.tv_sec;
	result->tv_usec = x.tv_usec - y.tv_usec;

	/* Return 1 if result is negative. */
	return x.tv_sec < y.tv_sec;
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count)
{
	register unsigned long sum = 0;
	while (count > 1)
	{
		sum += *addr++;
		count -= 2;
	}
	// if any bytes left, pad the bytes and add
	if (count > 0)
	{
		sum += ((*addr) & htons(0xFF00));
	}
	// Fold sum to 16 bits: add carrier to result
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	// one's complement
	sum = ~sum;
	return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr *iphdrp)
{
	iphdrp->check = 0;
	iphdrp->check = compute_checksum((unsigned short *)iphdrp, iphdrp->ihl << 2);
}

struct icmp_packet
{
	struct icmphdr header;
	struct timeval data;	
};

#define print_raw(X) _print_raw((unsigned char *)&X, sizeof(X))
void _print_raw(unsigned char *data, size_t length) {

	for (size_t i = 0; i < length; i++)
	{
		printf("%.2X ", data[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	struct iphdr raw_ip = {
		.version = IPVERSION,
		.ihl = (sizeof(raw_ip) / 4),		   // may need change
		.tos = IPTOS_CLASS_CS2,				   // type of service //should be good
		.tot_len = sizeof(struct iphdr) + sizeof(struct icmp_packet), //! Total length of datagram //may need change
		.id = 0,
		.frag_off = 0,
		.ttl = 64,
		.protocol = IPPROTO_ICMP,
		.check = 0, // checksum value before actually making the checksum
	};

	struct in_addr ip_destination = {};

	inet_pton(AF_INET, argv[1], &ip_destination);
	print_in_addr(&ip_destination);

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
		.ai_next = NULL};

	struct addrinfo *address_info;
	int getaddrinfo_error = getaddrinfo(hostname, NULL, &hints, &address_info);
	if (getaddrinfo_error != 0)
	{
		printf("getaddrinfo: %s\n", gai_strerror(getaddrinfo_error));
		return 1;
	}
	// address_info.
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)address_info->ai_addr;
	print_in_addr(&ipv4->sin_addr);
	freeaddrinfo(address_info);

	raw_ip.saddr = ipv4->sin_addr.s_addr;
	raw_ip.daddr = ip_destination.s_addr;
	compute_ip_checksum(&raw_ip);

	printf("ip_checksum: %x\ninternet_checksum: %x\n", compute_checksum((uint16_t *)&raw_ip, sizeof(raw_ip)), internet_checksum((uint16_t *)&raw_ip, sizeof(raw_ip)));

	struct icmp_packet icmp;

	// struct icmphdr *icmp =;
	MEMZERO(icmp);
	icmp.header.type = ICMP_ECHO;
	icmp.header.code = 0;
	icmp.header.checksum = 0;
	icmp.header.un.echo.sequence = 0;
	icmp.header.un.echo.id = 42;

	int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (raw_socket == -1)
	{
		perror("ft_ping: socket:");
		return 1;
	}

	//Enable the TTL and TIMESTAMP for a tcp (icmp?) packet
	int enable = 1;
	setsockopt(raw_socket, SOL_SOCKET, SO_TIMESTAMP, &enable, sizeof(enable));

	struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr = ip_destination, .sin_port = 0};

	while (1)
	{
		printf("\n\nPING:\n");

		gettimeofday(&icmp.data, NULL);
		printf("icmp_time: %lis%lims\n", icmp.data.tv_sec, icmp.data.tv_usec);

		struct timeval ping_timeval = icmp.data;
		icmp.header.checksum = 0;
		icmp.header.un.echo.sequence = icmp.header.un.echo.sequence + 1;
		icmp.header.checksum = internet_checksum((uint16_t *)&icmp, sizeof(icmp));
		printf("ping icmp.header.checksum = %u\n", icmp.header.checksum);
		uint16_t reversed = internet_checksum((uint16_t *)&icmp, sizeof(icmp));
		printf("ping icmp.header.checksum reversed = %u\n", reversed);
		printf("ping icmp echo sequence: %i\n", icmp.header.un.echo.sequence);
		
		ssize_t write_result = sendto(raw_socket, &icmp, sizeof(icmp), 0, (struct sockaddr *)&dest, sizeof(dest));
		if (write_result == -1)
		{
			perror("socket: write");
			return 1;
		}

		printf("bytes writen to socket:%li\n", write_result);

		char buf[BUFSIZ];
		char cbuf[BUFSIZ];
		struct msghdr msg;
		struct iovec iov;

		iov.iov_base = buf;
		memset(buf, 0, ARRAY_BYTES(buf));
		iov.iov_len = ARRAY_BYTES(buf) - 1;
		msg.msg_name = NULL;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = ARRAY_BYTES(cbuf);
		
		recv_label:
		printf("\n\nPONG:\n");
		////RECEIVED A RESPONSE FROM ICMP ECHO
		ssize_t recv_result = recvmsg(raw_socket, &msg, MSG_WAITALL);
		if (recv_result == -1)
		{
			perror("socket: recvmsg");
		}
		printf("bytes recv from socket:%li\n", recv_result);
		//Getting the ip and verifying it's checksum
		struct iphdr *pong_ip = iov.iov_base;
		int ip_checksum = internet_checksum((uint16_t *)pong_ip, sizeof(*pong_ip));
		printf("pong ip header checksum%i\n", ip_checksum);

		//We get the icmp header by adding the size of the ip header, which can be between 20 and 60 of size
		//That's why we use ip_header_length * (sizeof a 32byte)
		struct icmp_packet *pong_icmp = (struct icmp_packet *)(iov.iov_base + pong_ip->ihl*4);
		
		int icmp_checksum = internet_checksum((uint16_t *)pong_icmp, sizeof(*pong_icmp));
		printf("pong icmp header checksum%i\n", icmp_checksum);
		
		//Getting received packet source and destination address for debugging
		struct in_addr tmp = {.s_addr = pong_ip->daddr};
		printf("\npong daddr\n");
		print_in_addr(&tmp);
		tmp.s_addr = pong_ip->saddr;
		printf("\npong saddr\n");
		print_in_addr(&tmp);

		//The time to live of the received packet
		printf("pong_ip ttl: %i\n", pong_ip->ttl);
		printf("pong_ip ihl %i\n", pong_ip->ihl * 4);

		struct cmsghdr *cmsg;
		struct timeval tm_recvmsg;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			if (cmsg->cmsg_level == SOL_SOCKET &&
				cmsg->cmsg_type == SCM_TIMESTAMP)
			{
				memcpy(&tm_recvmsg, CMSG_DATA(cmsg), sizeof(tm_recvmsg));
				break;
			}
		}
		if (cmsg == NULL)
		{
			printf("cmsg error\n");
		}
		// pong_icmp->header.un.echo.id = pong_icmp->header.un.echo.id;
		// pong_icmp->header.un.echo.sequence = pong_icmp->header.un.echo.sequence;
		struct timeval tm_timediff;
		MEMZERO(tm_timediff);
		// timeval_subtract(&tm_timediff, tm_recvmsg, tm_current);
		printf("id: %i seq: %i\n", pong_icmp->header.un.echo.id, pong_icmp->header.un.echo.sequence);
		printf("pong icmp:\n");
		printf("icmp type = %i\n", pong_icmp->header.type);
		printf("icmp code = %i\n", pong_icmp->header.code);
		printf("icmp id = %i\n", pong_icmp->header.un.echo.id);
		printf("icmp seqence = %i\n", pong_icmp->header.un.echo.sequence);
		printf("icmp checksum = %i\n", pong_icmp->header.checksum);
		printf("icmp checksum reversed = %i\n", internet_checksum((uint16_t *)pong_icmp, sizeof(*pong_icmp)));

		if (pong_icmp->header.type != ICMP_ECHOREPLY) {
			printf("icmp type isn't echoreply\n");
			goto recv_label;
		}

		printf("icmp_packet = "),
		print_raw(icmp);
		printf("pong_packet = ");
		print_raw(*pong_icmp);
		// _print_raw(((unsigned char *)&pong->icmp), sizeof(&pong_icmp->header));

		// struct timeval tm_current = pong_icmp->data;
		ping_timeval = pong_icmp->data;

		struct timeval pong_timeval;
		gettimeofday(&pong_timeval, NULL);
		// tm_current.tv_sec = ntohs(tm_current.tv_sec);
		// tm_current.tv_usec = ntohs(tm_current.tv_usec);
		// print_raw(&pong);
		// tm_current.tv_sec = ntohl(tm_current.tv_sec);
		// tm_current.tv_usec = ntohl(tm_current.tv_usec);
		// printf("recvmsg time: %lis%lims\n", tm_recvmsg.tv_sec, tm_recvmsg.tv_usec);
		
		printf("ping_time: %lis%lims\n", ping_timeval.tv_sec, ping_timeval.tv_usec);
		printf("pong_time: %lis%lims\n", pong_timeval.tv_sec, pong_timeval.tv_usec);
		
		tm_timediff.tv_sec = pong_timeval.tv_sec - ping_timeval.tv_sec;
		tm_timediff.tv_usec = pong_timeval.tv_usec - ping_timeval.tv_usec;
		printf("diff: %lis%lims\n", tm_timediff.tv_sec, tm_timediff.tv_usec);

		sleep(1);
		// printf("%.2f ms\n", ms);
		// printf("ping of %li s %li ms\n", tm_timediff.tv_sec, tm_timediff.tv_usec);
	}
}
