#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "header.h"
#include "bm.h"

BmCtx* ctx;
int check_str(Prepare* pre){
    uint32_t txt_len = pre->payload;
    uint16_t pat_len = strlen(pre->argv2);

    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)pre->argv2, pat_len);
    unsigned char* found = BoyerMoore((uint8_t*)pre->argv2, pat_len, (const uint8_t *)pre->pay_packet, txt_len, ctx);
    int flag = 0;
    if (found == NULL)
        printf("not found\n");
    else{
        printf("found %ld\n", found - pre->pay_packet);
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

int getspace(Prepare* pre){
    char* get = "GET ";
    uint32_t txt_len = pre->payload;
    uint16_t pat_len = strlen(get);

    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)get, pat_len);
    unsigned char* found = BoyerMoore((uint8_t*)get, pat_len, (const uint8_t *)pre->pay_packet, txt_len, ctx);
    int flag = 0;
    if (found == NULL) // https
        printf("not found\n");
    else{
        printf("found get %ld\n", found - pre->pay_packet); // http
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
    if(direction==Forward){ //http, https - rst
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet;
        if(tcp->th_flags ==0x18) {
            tcp->th_flags = 0x04;
            tcp->th_sum = TcpCheckSum((struct libnet_ipv4_hdr*)pre->ip_packet,(struct libnet_tcp_hdr*)pre->tcp_packet,(char*)pre->pay_packet,pre->payload);
        }
        int res = pcap_sendpacket(pre->pcap, pre->packet, pre->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
    }
    else if(type==Rst){//https - rst
        struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet;
        u_char * relay_packet = (u_char*)malloc(pre->caplen);
        memcpy(relay_packet,pre->packet,pre->caplen);

        ((struct libnet_ethernet_hdr*)relay_packet)->ether_dhost = ethernet->ether_shost;
        ((struct libnet_ethernet_hdr*)relay_packet)->ether_shost = pre->my_mac;
        relay_packet+=sizeof(struct libnet_ethernet_hdr);
        printf("%d",((struct libnet_ipv4_hdr*)relay_packet)->ip_p);
        in_addr_t ip_src = ((struct libnet_ipv4_hdr*)relay_packet)->ip_src.s_addr;
        ((struct libnet_ipv4_hdr*)relay_packet)->ip_src.s_addr = ((struct libnet_ipv4_hdr*)relay_packet)->ip_dst.s_addr;
        ((struct libnet_ipv4_hdr*)relay_packet)->ip_dst.s_addr = ip_src;
        relay_packet += ((struct libnet_ipv4_hdr*)relay_packet)->ip_hl*5;

        if(((struct libnet_tcp_hdr*)relay_packet)->th_flags==0x18)((struct libnet_tcp_hdr*)relay_packet)->th_flags = 0x04; //rst

        int res = pcap_sendpacket(pre->pcap, pre->packet, pre->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
    }
    //http - fin
}

int parsing(Prepare* pre){
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet;
    if(ntohs(ethernet->ether_type)!=IPv4){
        fprintf(stderr,"This is not IP Packet\n");
        return 0;
    }
    pre->ether_packet=pre->packet+sizeof(struct libnet_ethernet_hdr);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet;
    if(ip->ip_p!=TCP){
        fprintf(stderr,"This is not TCP Packet\n");
        return 0;
    }
    //printf("%x\n",ip->ip_len);
    pre->tcp_packet = pre->ether_packet + ip->ip_hl*5;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet;
    pre->pay_packet = pre->tcp_packet+ (tcp->th_off)*4;

    int payload_len = pre->caplen - sizeof(pre->pay_packet);
    pre->payload = payload_len;
    //printf("%d",payload_len);
    //BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)pre->packet, pat_len);
    if(check_str(pre))/*if data exist*/
    {
       dump(pre->pay_packet,payload_len);
       if(getspace(pre)){//http
           sendPacket(pre,Forward, Rst,NULL);
       }
    }
    return 1;
}
