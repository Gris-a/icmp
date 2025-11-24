#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define BUFFER_SIZE ETH_FRAME_LEN
#define DNS_PORT 53

static const char *FILTER_IP; 
#define FILTER_IP_BASE  "10.0.0."

static char packet[BUFFER_SIZE];
static ssize_t packet_size;

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

static const char *scourage_of_iron_cannibal_corpse[] = {
    "In.thrall.to.the.evil.lord",
    "A.procession.of.the.damned",
    "Sweating.blood.to.serve.the.beast",
    "Desolation.of.their.souls",
    "They.slave.in.fire",
    "Whips.of.Hades.at.their.backs",
    "The.Scourge.of.Iron",
    "Hell-src.eternal.pact",
    "Lash.them",
    "Rip.their.skin",
    "Scourge.of.Iron",
    "Rending.flesh",
    "On.earth.they.lived.by.force",
    "Now.the.villains.march.in.chains",
    "Men.of.violence.doomed.in.death",
    "Their.reward.for.a.life.of.sin",
    "They.slave.for.eons",
    "There.will.be.no.relief",
    "Mere.pawns.of.evil",
    "Used.and.then.enslaved",
    "Lash.them",
    "Rip.their.skin",
    "Scourge.of.Iron",
    "Rending.flesh",
    "Lash",
    "Rip.their.skin",
    "Scourge.of.Iron",
    "Rending.flesh",
    "Demonic.sadists",
    "Flay.the.damned.with.steel",
    "The.whip.strips.flesh",
    "Torments.beyond.the.material.world",
    "Skinless.bleeding",
    "Robbed.of.pride.and.power",
    "In.the.grip.of.the.infernal",
    "And.the.evil.will.not.die",
    "Iron.whip.will.be.relentless",
    "And.the.pain.will.never.end",
    "Lash.them",
    "Rip.their.skin",
    "Scourge.of.Iron",
    "Rending.flesh",
    "Lash",
    "Rip.their.skin",
    "Scourge.of.Iron",
    "Rending.flesh",
};
static const size_t n_hosts = sizeof(scourage_of_iron_cannibal_corpse) / sizeof(char *);

int raw_socket(const char *if_name) {
    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = if_nametoindex(if_name)
    };

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    
    return sock;
}

uint16_t checksum(uint16_t *buf, ssize_t len) {
    uint32_t sum = 0;
    
    for (;len > 1; len -= 2) {
        sum += *buf++;
    }
    
    if (len == 1) {
        sum += *(char*)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

void build_ttl_exceeded(int ttl) {
    char src_ip[16];
    sprintf(src_ip, "%s%d", FILTER_IP_BASE, ttl - 1);

    struct in_addr src_addr;
    inet_pton(AF_INET, src_ip, &src_addr);

    packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

    struct ethhdr *eth = (struct ethhdr *)packet;

    unsigned char h_tmp[ETH_ALEN]; 
    memcpy(h_tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, h_tmp, ETH_ALEN);
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    char origin_data[sizeof(struct iphdr) + 8];
    memcpy(origin_data, ip, sizeof(origin_data));

    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
    ip->ttl = 64;
    ip->daddr = ip->saddr;
    ip->saddr = src_addr.s_addr;

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    icmp->type = ICMP_TIME_EXCEEDED;
    icmp->code = 0;
    icmp->un.gateway = 0;
    
    char *data = (char *)(icmp + 1);
    memcpy(data, origin_data, sizeof(origin_data));

    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));

    icmp->checksum = 0;
    icmp->checksum = checksum((uint16_t *)icmp, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
}

void build_echo_reply(void) {
    struct in_addr src_addr;
    inet_pton(AF_INET, FILTER_IP, &src_addr);

    struct ethhdr *eth = (struct ethhdr *)packet;

    unsigned char h_tmp[ETH_ALEN]; 
    memcpy(h_tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, h_tmp, ETH_ALEN);
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    ip->ttl = 64;

    ip->daddr = ip->saddr;
    ip->saddr = src_addr.s_addr;

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;
    
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));

    icmp->checksum = 0;
    icmp->checksum = checksum((uint16_t *)icmp, packet_size - sizeof(struct ethhdr) - sizeof(struct iphdr));
}

void encode_dns_name(char *dest, const char *src) {
    while (*src) {
        char *len = dest++;
        while (*src && *src != '.') {
            *dest++ = *src++;
        }
        *len = dest - len - 1;
        if (*src == '.') src++;
    }
    *dest = 0;
}

void build_dns_response(int ttl) {
    struct ethhdr *eth = (struct ethhdr *)packet;

    unsigned char h_tmp[ETH_ALEN]; 
    memcpy(h_tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, h_tmp, ETH_ALEN);

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    in_addr_t tmpaddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmpaddr;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    udp->check = 0;

    uint16_t tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp;

    struct dnshdr *dns = (struct dnshdr *)(udp + 1);
    char *dns_data = (char *)(dns + 1);

    dns->flags = htons(0x8580);
    dns->ancount = htons(1);

    char *response_ptr = (char *)(packet + packet_size);

    *(uint16_t *)response_ptr = htons(0xC00C);
    response_ptr += 2;

    *(uint16_t *)response_ptr = htons(12);
    response_ptr += 2;

    *(uint16_t *)response_ptr = htons(1);
    response_ptr += 2;
    
    *(uint32_t *)response_ptr = htonl(228);
    response_ptr += 4;

    *(uint16_t *)response_ptr = htons(strlen(scourage_of_iron_cannibal_corpse[ttl]) + 2);
    response_ptr += 2;

    encode_dns_name(response_ptr, scourage_of_iron_cannibal_corpse[ttl]);
    response_ptr += strlen(scourage_of_iron_cannibal_corpse[ttl]) + 2;

    udp->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr) + response_ptr - dns_data);
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + response_ptr - dns_data);

    packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + response_ptr - dns_data;

    ip->check = 0;
    ip->check = checksum((uint16_t*)ip, sizeof(struct iphdr));
}

int filter_icmp(void) {
    struct in_addr filter_addr;

    struct ethhdr *eth = (struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return -1;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if(ip->protocol != IPPROTO_ICMP) return -1;

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    if (icmp->type != ICMP_ECHO) return -1;
    
    inet_pton(AF_INET, FILTER_IP, &filter_addr);
    if (ip->daddr != filter_addr.s_addr) return -1;

    return ip->ttl;
}

int filter_dns(void) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    if (ip->protocol != IPPROTO_UDP) {        
        return -1;
    }

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if (ntohs(udp->dest) != DNS_PORT) {
        return -1;
    }

    struct dnshdr *dns = (struct dnshdr *)(udp + 1);
    char *dns_data = (char *)(dns + 1);

    char len = *dns_data;
    dns_data += (len + 1);
    
    char sign[] = {0x01, '0', 0x01, '0',  0x02, '1', '0'};
    if (memcmp(dns_data, sign, sizeof(sign)) == 0) {
        dns_data -= len;
        int ttl = 0;
        for (size_t i = 0; i < len; ++i) {
            ttl *= 10;
            ttl += *dns_data - '0';
            ++dns_data;
        }
        return ttl;
    }

    return -1;
}

void forward_packets(int src, int dst) {
    while (true) {
        packet_size = recv(src, packet, BUFFER_SIZE, 0);
        send(dst, packet, packet_size, 0);
    }
}

void traceroute_filter_forward_packets(int src, int dst) {
    while (true) {
        packet_size = recv(src, packet, BUFFER_SIZE, 0);

        int ttl = filter_icmp();
        if (ttl != -1) {
            (ttl <= n_hosts) ? build_ttl_exceeded(ttl) 
                             : build_echo_reply();
            send(src, packet, packet_size, 0);
            continue;
        } 

        ttl = filter_dns();
        if (ttl != -1) {
            build_dns_response(ttl);
            send(src, packet, packet_size, 0);
            continue;
        }

        send(dst, packet, packet_size, 0);
    }
}

int main(int argc, const char *argv[]) {
    FILTER_IP = argv[1];
    int sock1 = raw_socket(argv[2]);
    int sock2 = raw_socket(argv[3]);
    
    pid_t pid = fork();
    if (pid) forward_packets(sock2, sock1);
    traceroute_filter_forward_packets(sock1, sock2);
}