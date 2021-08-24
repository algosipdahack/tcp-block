#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "header.h"
#include "bm.h"

BmCtx* ctx;
int check_str(const unsigned char *data,char* bad){
    uint32_t txt_len = strlen((char*)data);
    uint16_t pat_len = strlen(bad);

    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)bad, pat_len);
    unsigned char* found = BoyerMoore((uint8_t*)bad, pat_len, (const uint8_t *)data, txt_len, ctx);
    int flag = 0;
    if (found == NULL)
        printf("not found\n");
    else{
        printf("found %ld\n", found - data);
        flag = 1;
    }
    //BoyerMooreCtxDeInit(ctx);
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

int getspace(const u_char* packet){
    char* get = "GET ";
    uint32_t txt_len = strlen((char*)packet);
    uint16_t pat_len = strlen(get);

    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)get, pat_len);
    unsigned char* found = BoyerMoore((uint8_t*)get, pat_len, (const uint8_t *)packet, txt_len, ctx);
    int flag = 0;
    if (found == NULL) // https
        printf("not found\n");
    else{
        printf("found get %ld\n", found - packet); // http
        flag = 1;
    }
    //BoyerMooreCtxDeInit(ctx);
    return flag;
}

u_short CheckSum(u_short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(u_short);
    }
    if(size)
        cksum += *(u_short*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (u_short)(~cksum);
}


u_short TcpCheckSum(ip* iph,tcp* tcph,char* data,int size)
{
    tcph->th_sum=0;
    PSD_HEADER psd_header;
    psd_header.m_daddr=iph->ip_dst;
    psd_header.m_saddr=iph->ip_src;
    psd_header.m_mbz=0;
    psd_header.m_ptcl=IPPROTO_TCP;
    psd_header.m_tcpl=htons(sizeof(tcp)+size);

    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER));
    memcpy(tcpBuf+sizeof(PSD_HEADER),tcph,sizeof(tcp));
    memcpy(tcpBuf+sizeof(PSD_HEADER)+sizeof(tcp),data,size);
    return tcph->th_sum=CheckSum((u_short *)tcpBuf,
        sizeof(PSD_HEADER)+sizeof(tcp)+size);
}

int sendPacket(Prepare* pre,Direction direction,BlockType type,char* message){
    if(direction==Forward){
        struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet;
        ethernet->ether_shost = pre->my_mac;
        pre->packet+=sizeof(struct libnet_ethernet_hdr);

        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->packet;
        pre->packet += ip->ip_hl*5;
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->packet;
        if(tcp->th_flags ==0x18) tcp->th_flags = 0x04;
        int res = pcap_sendpacket(pre->pcap, pre->packet, pre->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
        free(pre->pcap);
    }
    if(type==Rst){//https - rst
        struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet;
        ethernet->ether_dhost = ethernet->ether_shost;
        ethernet->ether_shost = pre->my_mac;

        pre->packet+=sizeof(struct libnet_ethernet_hdr);

        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->packet;

        struct in_addr ip_src = ip->ip_src;
        ip->ip_src = ip->ip_dst;
        ip->ip_dst = ip_src;

        pre->packet += ip->ip_hl*5;

        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->packet;

        if(tcp->th_flags ==0x18) tcp->th_flags = 0x04; //rst
        int res = pcap_sendpacket(pre->pcap, pre->packet, pre->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
        free(pre->pcap);
    }
    //http - fin
}

int parsing(Prepare* pre){
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet;
    if(ntohs(ethernet->ether_type)!=IPv4){
        fprintf(stderr,"This is not IP Packet\n");
        return 0;
    }
    pre->packet+=sizeof(struct libnet_ethernet_hdr);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->packet;
    if(ip->ip_p!=TCP){
        fprintf(stderr,"This is not TCP Packet\n");
        return 0;
    }
    //printf("%x\n",ip->ip_len);
    pre->packet += ip->ip_hl*5;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->packet;
    pre->packet += (tcp->th_off)*4;

    int payload_len = pre->caplen - sizeof(pre->packet);
    //printf("%d",payload_len);
    //BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)pre->packet, pat_len);
    if(check_str(pre->packet,pre->argv2))/*if data exist*/
    {
       dump(pre->packet,payload_len);
       if(getspace(pre->packet)){//http
           printf("dd");
           sendPacket(pre,Forward, Rst,NULL);
       }
    }
    return 1;
}
