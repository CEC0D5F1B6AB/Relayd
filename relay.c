#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>

#include "log.h"
#include "relay.h"
#include "nat.h"
#include "utils.h"
#include "ping.h"
#include "dns.h"

int start_relay(char *lan, char *wan)
{
    //create epoll list
    int epoll_fd = epoll_create(MAXEVENTS);
    if (epoll_fd < 0)
    {
        perror("epoll_create");
        return (-1);
    }

    //open wan interface
    int wan_fd = open_device(epoll_fd, wan);
    if (wan_fd < 0)
        return (-1);

    //get network info
    if (get_net_info(wan) < 0)
        return -1;

    //open lan interface
    int lan_fd = open_device(epoll_fd, lan);
    if (lan_fd < 0)
        return (-1);

    //define
    static int i, fd, nfds;
    static ssize_t size;
    static char buf[PKT_BUF_SIZE];
    static struct packet_hdr *packet = (struct packet_hdr *)buf; //nat packet
    static struct epoll_event epoll_events[MAXEVENTS];
    //loop
    while (!stop_flag)
    {
        nfds = epoll_wait(epoll_fd, epoll_events, MAXEVENTS, -1);
        //process events
        for (i = 0; i < nfds; i++)
        {
            switch (epoll_events[i].events)
            {
            case EPOLLIN: // data comming
                fd = epoll_events[i].data.fd;
                // recv data to buf
                size = recv(fd, packet, PKT_BUF_SIZE, 0);
                if (size <= 0)
                    break;
                // process packet
                if (process_packet((fd == wan_fd ? DNAT : SNAT), packet) != ACCEPT)
                    break;
                // relay
                send((fd == wan_fd ? lan_fd : wan_fd), packet, size, 0);
                break;
            default:
                logger(ERROR, "unknow event type\n");
                return -1;
            }
        }
        //process timer ping
        timer_ping(wan_fd, buf);
        //trigger dns
        timer_dns();
    }

    //release resource
    close(epoll_fd);
    close(lan_fd);
    close(wan_fd);

    return 0;
}