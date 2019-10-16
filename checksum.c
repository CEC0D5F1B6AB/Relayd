#include "checksum.h"

/*incremental update IP ,TCP, UDP checksum, 
implemented in C according with RFC1624, used subtraction to update checksum*/
inline uint16_t update_checksum_modified(uint16_t old_csum, uint16_t old_field, uint16_t new_field)
{
	uint32_t csum = (~old_csum & 0xFFFF) + (~old_field & 0xFFFF) + new_field;
	csum = (csum >> 16) + (csum & 0xFFFF);
	csum += (csum >> 16);
	return ~csum;
}

static inline uint16_t in_checksum(uint16_t *addr, size_t len)
{
	size_t nleft = len, sum = 0;
	uint16_t *w = addr, answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(uint8_t *)&answer = *(uint8_t *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum;
}

inline void update_iphdr_checksum(struct iphdr *iphdr)
{
	iphdr->check = 0;
	iphdr->check = in_checksum((uint16_t *)iphdr, sizeof(struct iphdr));
}

inline void update_tcp_checksum(struct iphdr *iphdr)
{
	//save iphdr
	struct iphdr iphdr_b;
	memcpy(&iphdr_b, iphdr, sizeof(struct iphdr));

	uint16_t remain_len = ntohs(iphdr->tot_len) - iphdr->ihl * 4; // remain len

	struct pseudo_IP_header
	{
		uint32_t source, dest;
		uint8_t zero_byte, protocol;
		uint16_t len;
	} *pshdr = (struct pseudo_IP_header *)((uint8_t *)iphdr + (iphdr->ihl * 4) - sizeof(struct pseudo_IP_header));
	pshdr->source = iphdr_b.saddr;
	pshdr->dest = iphdr_b.daddr;
	pshdr->zero_byte = 0;
	pshdr->protocol = iphdr_b.protocol;
	pshdr->len = htons(remain_len);

	struct tcphdr *tcphdr = (struct tcphdr *)((uint8_t *)pshdr + sizeof(struct pseudo_IP_header));
	tcphdr->check = 0;
	tcphdr->check = in_checksum((uint16_t *)pshdr, sizeof(struct pseudo_IP_header) + remain_len);

	//recovery iphdr
	memcpy(iphdr, &iphdr_b, sizeof(struct iphdr));
}

inline void update_udp_checksum(struct iphdr *iphdr)
{
	//save iphdr
	struct iphdr iphdr_b;
	memcpy(&iphdr_b, iphdr, sizeof(struct iphdr));

	uint16_t remain_len = ntohs(iphdr->tot_len) - iphdr->ihl * 4; // remain len

	struct pseudo_IP_header
	{
		uint32_t source, dest;
		uint8_t zero_byte, protocol;
		uint16_t len;
	} *pshdr = (struct pseudo_IP_header *)((uint8_t *)iphdr + (iphdr->ihl * 4) - sizeof(struct pseudo_IP_header));
	pshdr->source = iphdr_b.saddr;
	pshdr->dest = iphdr_b.daddr;
	pshdr->zero_byte = 0;
	pshdr->protocol = iphdr_b.protocol;
	pshdr->len = htons(remain_len);

	struct udphdr *udphdr = (struct udphdr *)((uint8_t *)pshdr + sizeof(struct pseudo_IP_header));
	udphdr->check = 0;
	udphdr->check = in_checksum((uint16_t *)pshdr, sizeof(struct pseudo_IP_header) + remain_len);

	//recovery iphdr
	memcpy(iphdr, &iphdr_b, sizeof(struct iphdr));
}

inline void update_icmp_checksum(struct icmphdr *icmp_hdr, size_t padding_len)
{
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = in_checksum((uint16_t *)icmp_hdr, sizeof(struct icmp) + padding_len);
}