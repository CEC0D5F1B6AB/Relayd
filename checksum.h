#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/ethtool.h>

uint16_t update_checksum_modified(uint16_t old_csum, uint16_t old_field, uint16_t new_field);
void update_icmp_checksum(struct icmphdr *icmp_hdr, size_t padding_len);
void update_iphdr_checksum(struct iphdr *iphdr);
void update_udp_checksum(struct iphdr *iphdr);
void update_tcp_checksum(struct iphdr *iphdr);
