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

#include "log.h"
#include "checksum.h"
#include "nat.h"
#include "ping.h"
#include "dns.h"

int ping(int fd, char *buf, char *smac, uint32_t saddr)
{
    struct packet_hdr *packet = (struct packet_hdr *)buf;

    char msg[] = "1234567890";
    size_t msg_len = strlen(msg);
    size_t packet_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + msg_len;

    //ethhdr encode
    memcpy(packet->eth_hdr.h_dest, host.gw_mac, ETH_ALEN);
    memcpy(packet->eth_hdr.h_source, smac, ETH_ALEN);
    packet->eth_hdr.h_proto = ntohs(ETH_P_IP);

    //iphdr encode
    packet->ip_hdr.version = 4; //ipv4
    packet->ip_hdr.ihl = 5;     //head len
    packet->ip_hdr.tos = 0;     //flags?
    packet->ip_hdr.tot_len = htons(packet_len - sizeof(struct ethhdr));
    packet->ip_hdr.id = 0;
    packet->ip_hdr.frag_off = 0;
    packet->ip_hdr.ttl = 128;
    packet->ip_hdr.protocol = IPPROTO_ICMP;
    packet->ip_hdr.check = 0;
    //addr
    packet->ip_hdr.saddr = saddr;
    inet_aton(PING_SERVER, (struct in_addr *)&packet->ip_hdr.daddr);

    update_iphdr_checksum(&packet->ip_hdr);
    //finish iphdr encode

    //icmp encode
    packet->t.icmp_hdr.type = ICMP_ECHO;
    packet->t.icmp_hdr.code = 0;
    packet->t.icmp_hdr.checksum = 0;
    packet->t.icmp_hdr.un.echo.id = getpid();
    packet->t.icmp_hdr.un.echo.sequence = 1;

    char *icmp_msg = (char *)&packet->t.icmp_hdr + sizeof(struct icmphdr);
    memcpy(icmp_msg, msg, msg_len);

    update_icmp_checksum(&packet->t.icmp_hdr, msg_len);

    //send
    if (send(fd, buf, packet_len, 0) < 0)
    {
        perror("send");
        return -1;
    }
    logger(DEBUG, "ping : %s\n", inet_ntoa(*(struct in_addr *)&saddr));

    return (fd);
}

//return 1 is hook success
int hook_icmp(struct packet_hdr *packet)
{
    static int host_index;
    static struct timeval now;

    //check is our ping packet
    if (packet->t.icmp_hdr.type != ICMP_ECHOREPLY || packet->t.icmp_hdr.un.echo.id != getpid())
    {
        return ACCEPT;
    }

    // logger(DEBUG, "pong : %s->%s\n", inet_ntoa(*(struct in_addr *)&packet->ip_hdr.saddr), inet_ntoa(*(struct in_addr *)&packet->ip_hdr.daddr));

    //find the host
    int i;
    for (i = 1; i < host.count; i++)
    {
        if (host.entry[i].addr == packet->ip_hdr.daddr)
            break;
    }
    if (i >= host.count)
        return DROP; //no found
    host_index = i;

    //handle response
    gettimeofday(&now, NULL); //get current time
    host.entry[host_index].ping = now.tv_sec;
    if (host.valid < 1)
    {
        host.valid = host_index; // set the nat target index
        logger(DEBUG, "online : %s\n", inet_ntoa(*(struct in_addr *)&packet->ip_hdr.daddr));
    }

    return DROP;
}

void check_host_alive(int fd, char *buf)
{
    static int host_index;
    static struct timeval now;

    //check if nat enable
    if (host.enable == 0)
    {
        host.valid = 0; //set none host online
        return;
    }

    host_index = host.valid;
    gettimeofday(&now, NULL); //get current time

    if (host_index > 0 && now.tv_sec - host.entry[host_index].ping > HOST_PING_TIMEOUT)
    {
        host.valid = 0; //set none host online
        logger(DEBUG, "offline : %s\n", inet_ntoa(*(struct in_addr *)&host.entry[host_index].addr));
    }

    if (host_index < 1)
    {
        //ping all host
        int i;
        for (i = 1; i < host.count; i++)
        {
            ping(fd, buf, host.entry[i].mac, host.entry[i].addr);
        }
    }
    else
    {
        ping(fd, buf, host.entry[host_index].mac, host.entry[host_index].addr);
    }
}

void timer_ping(int fd, char *buf)
{
    static struct timeval timer, now;

    gettimeofday(&now, NULL); // refresh timer
    if (now.tv_sec - timer.tv_sec > TIMER_CYCLE_PING)
    {
        check_host_alive(fd, buf);
        gettimeofday(&timer, NULL); // refresh timmer
    }
}