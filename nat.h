#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/time.h>
#include <linux/if_packet.h>

#define MAX_NAT_ENTRIES 16384

#define NAT_PORT_OFFSET 0xc000 //65536-16384

#define MAX_HOST_ENTRIES 256

#define NAT_TIMEOUT 300 //second

#define DNAT 0
#define SNAT 1

#define ACCEPT 0 //relay the packet
#define DROP 1   // drop the packet

#pragma pack(1)
struct packet_hdr
{
    struct ethhdr eth_hdr;
    struct iphdr ip_hdr;
    union {
        struct tcphdr tcp_hdr;
        struct udphdr udp_hdr;
        struct icmphdr icmp_hdr;
    } t;
};
#pragma pack()

/* NAT table entry*/
struct
{
    struct
    {
        uint8_t host_index;
        uint16_t host_port;
        uint16_t wan_port;
        uint64_t timeout;
    } entry[MAX_NAT_ENTRIES];
    uint16_t index;
} nat;

/* HOST table entry*/
struct
{
    struct
    {
        char mac[ETH_ALEN];
        uint32_t addr;
        uint64_t ping;
    } entry[MAX_HOST_ENTRIES]; //0 is wan host
    char gw_mac[ETH_ALEN];
    uint32_t netmask;
    uint32_t brdaddr;
    uint8_t count;
    uint8_t valid;
    uint8_t enable;
} host;

int process_packet(int type, struct packet_hdr *packet);