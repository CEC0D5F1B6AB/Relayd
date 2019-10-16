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
#include "nat.h"

int open_device(int epoll_fd, char *interface){
    //create socket
	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0){
		perror("socket");
		return(-1);
	}
	//define struct
	struct ifreq ifr;
	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	//set read eth flags
	if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0 ){
		perror("ioctl");
		return(-1);
	}
    //set promisc flags
    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0 ){
		perror("ioctl");
		return(-1);
	}
    //bind interface
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0){
		perror("ioctl");
		return(-1);
	}
	struct sockaddr_ll addr;
	bzero(&addr, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll)) < 0){
		perror("bind");
		return(-1);
	}
    //define struct
    struct epoll_event ev;
	ev.data.fd = fd;
	ev.events = EPOLLIN;
	//add to epoll list
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0){
		perror("epll_ctl");
		return(-1);
	}

	return(fd);
}

int get_gateway_mac(char *device, unsigned char *mac){
	FILE *fp = fopen("/proc/net/arp", "r");
	if (fp == NULL) return -1;

    char i = 0, buf[256], smac[32], iface[IFNAMSIZ];
	memset(buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp) != NULL){
		if (i++ == 0) continue; //igonre first line
		sscanf(buf, "%*s %*s %*s %s %*s %s", (char *)&smac, (char *)&iface);
		if (strcmp(device, iface) == 0) {
			sscanf(smac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
			return 0;
		}
	}
	if(fp) fclose(fp);

	return -1;
}

int get_net_info(char *interface){
   int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0){
		perror("socket");
		return(-1);
	}
    
	//define struct
    int host_index = host.count % MAX_HOST_ENTRIES; //0 is wan host
	struct ifreq ifr;
    unsigned char mac[ETH_ALEN];
    struct sockaddr_in sin;
	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    //get eth mac
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
        perror("ioctl");
        return(-1);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(host.entry[host_index].mac, mac, ETH_ALEN);
    logger(DEBUG, "wan mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    //get eth addr
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
        perror("ioctl");
        return(-1);
    }
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    if(sin.sin_family != AF_INET){ //ipv4
        logger(ERROR, "wan addr not ipv4\n");
        return(-1);
    }
    host.entry[host_index].addr = sin.sin_addr.s_addr;
    logger(DEBUG, "wan addr : %s\n", inet_ntoa(*(struct in_addr *)&host.entry[host_index].addr));

    //get eth netmask
    if(ioctl(fd, SIOCGIFNETMASK, &ifr) < 0){
        perror("ioctl");
        return(-1);
    }
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    if(sin.sin_family != AF_INET){ //ipv4
        logger(ERROR, "wan netmask not ipv4\n");
        return(-1);
    }
    host.netmask = sin.sin_addr.s_addr;
    logger(DEBUG, "wan netmask : %s\n", inet_ntoa(*(struct in_addr *)&host.netmask));

    //get eth broadcast
    if(ioctl(fd, SIOCGIFBRDADDR, &ifr) < 0){
        perror("ioctl");
        return(-1);
    }
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    if(sin.sin_family != AF_INET){ //ipv4
        logger(ERROR, "wan brdaddr not ipv4\n");
        return(-1);
    }
    host.brdaddr = sin.sin_addr.s_addr;
    logger(DEBUG, "wan brdaddr : %s\n", inet_ntoa(*(struct in_addr *)&host.brdaddr));

    //get gateway mac
    if(get_gateway_mac(interface, mac) < 0){
        logger(ERROR, "wan gateway not found\n");
        return(-1);
    };
    memcpy(host.gw_mac, mac, ETH_ALEN);
    logger(DEBUG, "wan gateway : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if(fd) close(fd);

	return 0;
}
