#include "log.h"
#include "nat.h"
#include "checksum.h"
#include "ping.h"

static inline int get_nat_entry_by_snat(uint8_t *mac, uint32_t addr, uint16_t port)
{
    static int i, host_index, nat_index;
    static struct timeval now;

    //find the host
    for (i = 1; i < host.count; i++)
    {
        if (host.entry[i].addr == addr)
            break;
    }
    if (i >= host.count)
    { //if no found
        //add current host to host table
        host_index = (++host.count) % MAX_HOST_ENTRIES;
        memcpy(host.entry[host_index].mac, mac, ETH_ALEN);
        host.entry[host_index].addr = addr;
        logger(DEBUG, "new host : %s\n", inet_ntoa(*(struct in_addr *)&addr));
    }
    else
    {
        host_index = i;
    }

    gettimeofday(&now, NULL); //get current time
    for (i = 0; i < MAX_NAT_ENTRIES; i++)
    {
        if (nat.entry[i].host_index == host_index && nat.entry[i].host_port == port && now.tv_sec - nat.entry[i].timeout < NAT_TIMEOUT //check if timeout ?
        )
        {
            nat.entry[i].timeout = now.tv_sec;
            return i; //return index when found
        }
    }

    //nat entry no found
    //find a timeout nat enery
    for (i = 0; i < MAX_NAT_ENTRIES; i++)
    { //limit the max loop count
        nat_index = nat.index++;
        nat.index = nat.index % MAX_NAT_ENTRIES; //limit the max value is MAX_NAT_ENTRIES
        if (now.tv_sec - nat.entry[nat_index].timeout > NAT_TIMEOUT)
            break; //return current nat entry when availability
    }
    //create a nat
    nat.entry[nat_index].host_index = host_index;
    nat.entry[nat_index].host_port = port;
    nat.entry[nat_index].wan_port = htons(nat_index + NAT_PORT_OFFSET); // new port
    nat.entry[nat_index].timeout = now.tv_sec;
    logger(DEBUG, "new port : %s:%u->%u\n", inet_ntoa(*(struct in_addr *)&addr), port, nat_index + NAT_PORT_OFFSET);

    return nat_index;
}

static inline int find_index_by_dport(uint16_t port)
{
    static int nat_index;
    static struct timeval now;

    nat_index = port - NAT_PORT_OFFSET;
    gettimeofday(&now, NULL); //get now time
    if (nat_index < 0 || now.tv_sec - nat.entry[nat_index].timeout > NAT_TIMEOUT)
        return -1; //no found
    nat.entry[nat_index].timeout = now.tv_sec;
    return nat_index;
}

static inline void modified_addr(uint8_t proto, uint32_t *addr, uint32_t new_addr, uint16_t *ip_ck, uint16_t *ts_ck)
{
    //update checksum
    switch (proto)
    {
    case IPPROTO_TCP:
        *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 0 & 0xFFFF), (new_addr >> 0 & 0xFFFF));
        *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 16 & 0xFFFF), (new_addr >> 16 & 0xFFFF));
        *ts_ck = update_checksum_modified(*ts_ck, (*addr >> 0 & 0xFFFF), (new_addr >> 0 & 0xFFFF));
        *ts_ck = update_checksum_modified(*ts_ck, (*addr >> 16 & 0xFFFF), (new_addr >> 16 & 0xFFFF));
        break;
    case IPPROTO_UDP:
        if (*ip_ck != 0)
        { //optional
            *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 0 & 0xFFFF), (new_addr >> 0 & 0xFFFF));
            *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 16 & 0xFFFF), (new_addr >> 16 & 0xFFFF));
        }
        *ts_ck = update_checksum_modified(*ts_ck, (*addr >> 0 & 0xFFFF), (new_addr >> 0 & 0xFFFF));
        *ts_ck = update_checksum_modified(*ts_ck, (*addr >> 16 & 0xFFFF), (new_addr >> 16 & 0xFFFF));
        break;
    case IPPROTO_ICMP:
        if (*ip_ck != 0)
        { //optional
            *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 0 & 0xFFFF), (new_addr >> 0 & 0xFFFF));
            *ip_ck = update_checksum_modified(*ip_ck, (*addr >> 16 & 0xFFFF), (new_addr >> 16 & 0xFFFF));
        }
        break;
    }

    //replace ip
    *addr = new_addr;
}

static inline void modified_port(uint8_t proto, uint16_t *port, uint16_t new_port, uint16_t *ts_ck)
{
    //update transport layer checksum
    *ts_ck = update_checksum_modified(*ts_ck, *port, new_port);
    //replace port
    *port = new_port;
}

static inline int process_dnat(uint8_t proto, uint8_t *mac, uint32_t *addr, uint16_t *port, uint16_t *ip_ck, uint16_t *ts_ck)
{
    static int nat_index, host_index;

    //check if the target ip is vaild
    if (host.valid > 0 && *addr != host.entry[host.valid].addr)
        return DROP;

    //find nat index
    nat_index = find_index_by_dport(ntohs(*port));
    if (nat_index < 0)
        return DROP;

    //do DNAT
    host_index = nat.entry[nat_index].host_index;
    memcpy(mac, host.entry[host_index].mac, ETH_ALEN);                     //replace mac
    modified_addr(proto, addr, host.entry[host_index].addr, ip_ck, ts_ck); //replace ip
    modified_port(proto, port, nat.entry[nat_index].host_port, ts_ck);     //replace port
    return ACCEPT;
}

static inline int process_snat(uint8_t proto, uint8_t *mac, uint32_t *addr, uint16_t *port, uint16_t *ip_ck, uint16_t *ts_ck)
{
    static int nat_index;

    //check the source addr is match network
    if ((*addr & host.netmask) != (host.brdaddr & host.netmask))
        return DROP;

    //find nat index
    nat_index = get_nat_entry_by_snat(mac, *addr, *port);
    if (nat_index < 0)
        return DROP;

    //do SNAT
    if (host.valid > 0)
    {                                                                          //target nat is vaild
        memcpy(mac, host.entry[host.valid].mac, ETH_ALEN);                     //replace mac
        modified_addr(proto, addr, host.entry[host.valid].addr, ip_ck, ts_ck); //replace ip
    }
    modified_port(proto, port, nat.entry[nat_index].wan_port, ts_ck); //replace port
    return ACCEPT;
}

int process_packet(int type, struct packet_hdr *packet)
{
    if (packet->eth_hdr.h_proto != ntohs(ETH_P_IP))
        return ACCEPT; // only process ip packet

    static uint8_t *dmac, *smac;
    static uint32_t *daddr, *saddr;
    static uint16_t *dport, *sport;
    static uint16_t *ip_ck, *ts_ck;
    static uint8_t proto;

    proto = packet->ip_hdr.protocol;
    switch (proto)
    {
    case IPPROTO_TCP:
        dport = (uint16_t *)&packet->t.tcp_hdr.dest;
        sport = (uint16_t *)&packet->t.tcp_hdr.source;
        ts_ck = (uint16_t *)&packet->t.tcp_hdr.check;
        break;
    case IPPROTO_UDP:
        dport = (uint16_t *)&packet->t.udp_hdr.dest;
        sport = (uint16_t *)&packet->t.udp_hdr.source;
        ts_ck = (uint16_t *)&packet->t.udp_hdr.check;
        if (*dport == htons(67) || *sport == htons(67))
            return ACCEPT; ////don't nat dhcp packet
        break;
    case IPPROTO_ICMP:
        dport = (uint16_t *)&packet->t.icmp_hdr.un.echo.id;
        sport = (uint16_t *)&packet->t.icmp_hdr.un.echo.id;
        ts_ck = (uint16_t *)&packet->t.icmp_hdr.checksum;
        if (type == DNAT)
            if (hook_icmp(packet) == DROP)
                return DROP; //hook the icmp packet
        break;
    default:
        return DROP; //don't nat other packet
    }

    ip_ck = (uint16_t *)&packet->ip_hdr.check;
    if (type == DNAT)
    {
        dmac = (uint8_t *)&packet->eth_hdr.h_dest;
        daddr = (uint32_t *)&packet->ip_hdr.daddr;
        return process_dnat(proto, dmac, daddr, dport, ip_ck, ts_ck);
    }
    else
    {
        smac = (uint8_t *)&packet->eth_hdr.h_source;
        saddr = (uint32_t *)&packet->ip_hdr.saddr;
        return process_snat(proto, smac, saddr, sport, ip_ck, ts_ck);
    }
}
