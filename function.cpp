#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "header.h"
#include "bm.h"


BmCtx* ctx;
int check_str(const unsigned char *data,char* bad){
    uint16_t pat_len = strlen(bad);
    uint32_t txt_len = strlen((char*)data);

    /*using BoyerMoore to find url*/
    printf("Bad Character table\n");
    for (int i = 0; i < ALPHABET_SIZE; i++) {
    if (ctx->bmBc[i] != pat_len)
        printf("%d(%c) = %d\n", i, i, ctx->bmBc[i]);
    }
    printf("\n");

    printf("Good Suffix table\n");
    for (int i = 0; i < pat_len; i++) {
        printf("%d(%c) %d\n", i, bad[i], ctx->bmGs[i]);
    }

    printf("\n");
    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)bad, pat_len);
    unsigned char* found = BoyerMoore((uint8_t*)bad, pat_len, data, txt_len, ctx);

    int flag = 0;
    if (found == NULL)
        printf("not found\n");
    else{
        printf("found %ld\n", found - data);
        flag = 1;
    }
    BoyerMooreCtxDeInit(ctx);
    return flag;
}
void dump(const unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}
int parsing(const u_char* packet,char* argv,bpf_u_int32 caplen){
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)packet;
    if(ntohs(ethernet->ether_type)!=IPv4){
        fprintf(stderr,"This is not IP Packet\n");
        return 0;
    }
    packet+=sizeof(struct libnet_ethernet_hdr);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)packet;
    if(ip->ip_p!=TCP){
        fprintf(stderr,"This is not TCP Packet\n");
        return 0;
    }
    printf("%x\n",ip->ip_len);
    packet += ip->ip_hl*5;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)packet;
    packet += (tcp->th_off)*4;

    int payload_len = caplen - sizeof(packet);
    printf("%d",payload_len);
    if(check_str(packet,argv))/*if data exist*/
    {
       dump(packet,payload_len);
    }

    return 1;
}
