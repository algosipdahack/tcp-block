#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "bm.h"
#include "mac.h"
#ifndef HEADER_H
#define HEADER_H
#define TCP 6
#define IPv4 0x800
#endif // HEADER_H
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <unistd.h>

typedef struct libnet_ethernet_hdr
{
    Mac  ether_dhost;/* destination ethernet address */
    Mac  ether_shost;/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
}ethernet;
typedef struct libnet_ipv4_hdr
{
    u_int8_t ip_v:4;       /* version */
    u_int8_t ip_hl:4;        /* header length */
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
}ip;
typedef struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t  th_x2:4;    /* (unused) */
    u_int8_t  th_off:4;
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define c    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
}tcp;

struct payload{
    u_int8_t  data[64];
};
enum Direction{
    Forward = 1,
    Backward = 2
};
enum BlockType{
    Rst = 0x04,
    Fin = 0x01
};
enum Protocol{
    Http = 1,
    Https = 2
};


struct TCPBlock{
    Direction direction;
    BlockType blockType;
    Protocol protocol;
};
struct PSD_HEADER{
    struct in_addr m_saddr;
    struct in_addr m_daddr;

    u_int8_t m_mbz;
    u_int8_t m_ptcl;
    u_int16_t m_tcpl;
};
struct Packet{
    int size;
    const u_char* packet;
};

struct Prepare{
    struct Packet pay_packet;
    struct Packet tcp_packet;
    struct Packet ip_packet;
    struct Packet ether_packet;
    struct Packet packet;
    Mac my_mac;
    pcap_t* pcap;
    char* argv1;
    char* argv2;
};

int parsing(Prepare* pre);
void payload(const u_char* packet,uint tot);
int check_str(Prepare* pre);
void print_ethernet(u_int8_t  ether_host[]);
void print_ip(uint32_t addr);
void dump(const unsigned char* buf, int size);
extern BmCtx* ctx;
Mac getMacAddress(char* dev);
void convrt_mac(const char *data, char *cvrt_str, int sz);
u_short TcpCheckSum(Prepare* pre,char* data,int size);
u_short CheckSum(u_short *buffer, int size);
void sendPacket(Prepare* pre,Direction direction,BlockType type,char* message);
void backward(u_char * relay_packet, Prepare* pre,BlockType type,char* message);
void print(Prepare(*pre));
