#define PING_SERVER "114.114.114.114"

#define TIMER_CYCLE_PING 5 //second

#define HOST_PING_TIMEOUT 15 //second

void timer_ping(int fd, char *buf);
int hook_icmp(struct packet_hdr *packet);