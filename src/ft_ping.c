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
// #include <asm-generic/socket.h> //SCM_TIMESTAMP

#include <unistd.h>
#include <string.h> //memset
#define MEMZERO(data) (memset(&data, 0, sizeof(data)))
#define ARRAY_BYTES(array) (sizeof(array) / sizeof(array[0]))
#include <sys/time.h> //struct timeval
#include <time.h>

//NI_MAXHOST defined into __USE_MISC in netdb.h for auto-complete
#ifndef __USE_MISC
# define __USE_MISC
#endif
#include <netdb.h> //getaddinfo


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
	struct timespec data;
};

#define print_raw(X) _print_raw((unsigned char *)&X, sizeof(X))
void _print_raw(unsigned char *data, size_t length) {

	for (size_t i = 0; i < length; i++)
	{
		printf("%.2X ", data[i]);
	}
	printf("\n");
}

void print_verbose(char *resolved_name, char *ip_str, struct iphdr *ip_header, struct icmp_packet *icmp, float time_ms, ssize_t packet_size) {
	printf("%lu bytes from ", packet_size);
	if (resolved_name[0] == '\0') {
		printf("%s: ", ip_str);
	} else {
		printf("%s (%s): ", resolved_name, ip_str);
	}
	printf("icmp_seq=%i ident=%i ttl=%i time=%.3f ms\n", icmp->header.un.echo.sequence, icmp->header.un.echo.id, ip_header->ttl, time_ms);
}

#include <math.h>
struct rtt_info {
	double min_rtt;
	double max_rtt;
	double sum_rtt;
	double mean;
	double M2; // for variance
	int count;
};

void rtt_info_init(struct rtt_info *rtts) {
	rtts->min_rtt = +INFINITY;
	rtts->max_rtt = -INFINITY;
	rtts->sum_rtt = 0;
	rtts->mean = 0;
	rtts->M2 = 0; // for variance
	rtts->count = 0;
}

void rtt_info_calculate(struct rtt_info *rtts, double current_rtt) {
	rtts->count++;

	// Update min/max
	if (current_rtt < rtts->min_rtt) {
		rtts->min_rtt = current_rtt;
	}
	if (current_rtt > rtts->max_rtt) {
		rtts->max_rtt = current_rtt;
	}

	// Update running mean and variance using Welford's algorithm
	double delta = current_rtt - rtts->mean;
	rtts->mean += delta / rtts->count;
	double delta2 = current_rtt - rtts->mean;
	rtts->M2 += delta * delta2;

	// sum for average if you want
	rtts->sum_rtt += current_rtt;
}

void rtt_info_print(struct rtt_info *rtts) {


	double mdev = sqrt(rtts->M2 / rtts->count);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", rtts->min_rtt, rtts->mean, rtts->max_rtt, mdev);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	pid_t pid = getpid();

	char *input = argv[1];
	struct rtt_info rtts;
	rtt_info_init(&rtts);

	int is_verbose = 1;

	//Name resolution
	struct addrinfo hints = {
		.ai_flags = AI_V4MAPPED | AI_CANONNAME,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
		.ai_addrlen = 0,
		.ai_addr = NULL,
		.ai_canonname = NULL,
		.ai_next = NULL};

	struct addrinfo *address_info = NULL;
	int getaddrinfo_status = getaddrinfo(input, NULL, &hints, &address_info);
	if (getaddrinfo_status != 0)
	{
		printf("getaddrinfo: %s\n", gai_strerror(getaddrinfo_status));
		return 1;
	}
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)address_info->ai_addr;
	char addr_string[INET_ADDRSTRLEN + 1];
	addr_string[INET_ADDRSTRLEN] = 0;
	inet_ntop(AF_INET, &ipv4->sin_addr, addr_string, sizeof(addr_string));
    char resolved_name[NI_MAXHOST];

    // Reverse resolution: address → name
    int status = getnameinfo(address_info->ai_addr, address_info->ai_addrlen,
                         resolved_name, sizeof resolved_name,
                         NULL, 0, NI_NAMEREQD);
    if (status != 0) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(status));
    }

    struct in_addr _test_ip;
	int input_is_ip = inet_pton(AF_INET, input, &_test_ip) == 1;
    if (input_is_ip) {
		resolved_name[0] = '\0';
	}


	//Icmp initialisation
	struct icmp_packet icmp;
	MEMZERO(icmp);
	icmp.header.type = ICMP_ECHO;
	icmp.header.code = 0;
	icmp.header.checksum = 0;
	icmp.header.un.echo.sequence = 0;
	icmp.header.un.echo.id = pid;

	int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (raw_socket == -1)
	{
		perror("ft_ping: socket:");
		return 1;
	}
	if (is_verbose) {
		printf("ping: sock4.fd = %i (socktype: SOCK_RAW), hints.ai_family: AF_INET\n", raw_socket);
		printf("\n");
	}
	printf("ai->ai_family: AF_INET, ai->ai_canonname: '%s'\n", address_info->ai_canonname);
	freeaddrinfo(address_info);

	struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr = ipv4->sin_addr, .sin_port = 0};

	printf("PING %s (%s) 56(84) bytes of data.\n", input, addr_string);

	int is_first_ping = 1;
	struct timespec first_ping_timespec;
	MEMZERO(first_ping_timespec);
	while (1)
	{
		clock_gettime(CLOCK_MONOTONIC, &icmp.data);

		struct timespec ping_timespec = icmp.data;
		icmp.header.checksum = 0;
		icmp.header.un.echo.sequence = icmp.header.un.echo.sequence + 1;
		icmp.header.checksum = internet_checksum((uint16_t *)&icmp, sizeof(icmp));

		unsigned char packet[64];
		MEMZERO(packet);
		memcpy(packet, &icmp, sizeof(icmp));
		ssize_t write_result = sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
		if (write_result == -1)
		{
			perror("socket: write");
			return 1;
		}

		char buf[64];
		char cbuf[64];
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
		
		//In case of bad icmp packet we go back to recv call
		recv_label:
		ssize_t recv_result = recvmsg(raw_socket, &msg, MSG_WAITALL);
		if (recv_result == -1)
		{
			perror("socket: recvmsg");
		}

		//We verify ip checksum of the entire packet
		struct iphdr *pong_ip = iov.iov_base;
		int ip_checksum = internet_checksum((uint16_t *)pong_ip, sizeof(*pong_ip));
		if (ip_checksum != 0) {
			printf("ip header checksum is invalid\n");
		}

		//We get the icmp header by adding the size of the ip header, which can be between 20 and 60 of size
		//That's why we use ip_header_length * (sizeof a 32byte)
		struct icmp_packet *pong_icmp = (struct icmp_packet *)(iov.iov_base + pong_ip->ihl*4);
		
		int icmp_checksum = internet_checksum((uint16_t *)pong_icmp, sizeof(*pong_icmp));
		if (icmp_checksum != 0) {
			printf("icmp header checksum is invalid\n");
		}

		//This will be called when sending a ping to localhost
		if (pong_icmp->header.type != ICMP_ECHOREPLY) {
			// printf("icmp type isn't echoreply\n");
			goto recv_label;
		}
		if (pong_icmp->header.un.echo.id != pid) {
			// printf("ping didn't originate from this process\n");
			goto recv_label;
		}

		if (pong_icmp->header.un.echo.sequence != icmp.header.un.echo.sequence) {
			goto recv_label;
		}

		//Get the stored time in the icmp data section
		ping_timespec = pong_icmp->data;

		struct timespec pong_timespec;
		clock_gettime(CLOCK_MONOTONIC, &pong_timespec);


		if (is_first_ping) {
			is_first_ping = 0;
			first_ping_timespec = ping_timespec;
		}

		//Calculate time difference
		double msec = (pong_timespec.tv_sec - ping_timespec.tv_sec) * 1000.0 +
                  (pong_timespec.tv_nsec - ping_timespec.tv_nsec) / 1e6;
		//We remove the ip header len from the total ip packet len received
		int bytes_received_count = ntohs(pong_ip->tot_len) - (pong_ip->ihl * 4);
		print_verbose(resolved_name, addr_string, pong_ip, pong_icmp, msec, bytes_received_count);
		sleep(1);
		rtt_info_calculate(&rtts, msec);
		rtt_info_print(&rtts);
	}
}
