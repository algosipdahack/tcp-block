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
    unsigned char* found = BoyerMoore((uint8_t*)pre->argv2, pat_len, (const uint8_t *)pre->pay_packet.packet, txt_len, ctx);
    int flag = 0;
    if (found == NULL)
        printf("not found\n");
    else{
        printf("found %ld\n", found - pre->pay_packet.packet);
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
    unsigned char* found = BoyerMoore((uint8_t*)get, pat_len, (const uint8_t *)pre->pay_packet.packet, txt_len, ctx);
    int flag = 0;
    if (found == NULL) // https
        printf("not found\n");
    else{
        printf("found get %ld\n", found - pre->pay_packet.packet); // http
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

u_short TcpCheckSum(Prepare* pre,char* data,int size)
{
    PSD_HEADER psd_header;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    tcp->th_sum=0;
    psd_header.m_daddr=ip->ip_dst.s_addr;
    psd_header.m_saddr=ip->ip_src.s_addr;
    psd_header.m_mbz=0;
    psd_header.m_ptcl=IPPROTO_TCP;
    psd_header.m_tcpl=htons(sizeof(tcp)+size);

    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER));
    memcpy(tcpBuf+sizeof(PSD_HEADER),tcp,sizeof(tcp));
    memcpy(tcpBuf+sizeof(PSD_HEADER)+sizeof(tcp),data,size);
    return tcp->th_sum=CheckSum((u_short *)tcpBuf,
        sizeof(PSD_HEADER)+sizeof(tcp)+size);
}
void backward(u_char * relay_packet, Prepare* pre,BlockType type,char* message){
    memcpy(&relay_packet,pre->packet.packet,pre->packet.size);
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet.packet;

    //change mac
    ethernet->ether_dhost = ethernet->ether_shost;
    ethernet->ether_shost = pre->my_mac;
    //printf("%x",pre->ether_packet.size);
    memcpy(&relay_packet,ethernet,pre->ether_packet.size);
    relay_packet+=sizeof(struct libnet_ethernet_hdr);

    //change ip
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    in_addr_t ip_src = ip->ip_src.s_addr;
    ip->ip_src.s_addr = ip->ip_dst.s_addr;
    ip->ip_dst.s_addr = ip_src;

    //cal ip_checksum
    char ipBuf[65536];
    memcpy(ipBuf,&relay_packet,sizeof(struct libnet_ipv4_hdr));
    ip->ip_sum = CheckSum((u_short *)ipBuf,pre->ip_packet.size);
    //printf("%x",pre->ip_packet.size);
    memcpy(&relay_packet,ip,pre->ip_packet.size);


    //cal tcp_checksum
    relay_packet += ((struct libnet_ipv4_hdr*)pre->ether_packet.packet)->ip_hl*5;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    if(tcp->th_flags==0x18){
        tcp->th_flags = type; //rst or fin
        //check checksum
        tcp->th_sum = TcpCheckSum(pre,(char*)pre->pay_packet.packet,pre->payload);
    }
    memcpy(&relay_packet,tcp,pre->tcp_packet.size);

    if(message!=NULL){
        relay_packet += ((struct libnet_tcp_hdr*)pre->tcp_packet.packet)->th_off*4;
        memcpy(&relay_packet,&message,sizeof(message));
        relay_packet -=sizeof(message);
        u_char* tmp = (u_char*)pre->pay_packet.packet;
        pre->pay_packet.size = sizeof(message);
        pre->tcp_packet.size = pre->tcp_packet.size-sizeof(tmp)+pre->pay_packet.size;
        pre->ip_packet.size = pre->ip_packet.size-sizeof(tmp)+pre->pay_packet.size;
        pre->ether_packet.size = pre->ether_packet.size-sizeof(tmp)+pre->pay_packet.size;
        pre->packet.size = pre->ether_packet.size;
    }
    relay_packet = relay_packet - (pre->ether_packet.size - pre->tcp_packet.size);
    memcpy((char*)pre->packet.packet,&relay_packet,pre->packet.size);
}
void sendPacket(Prepare* pre,Direction direction,BlockType type,char* message){
    if(direction==Forward){ //http, https - rst
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
        if(tcp->th_flags ==0x18) {
            printf("hihi\n\n");
            tcp->th_flags = 0x04;
        }
        tcp->th_sum = TcpCheckSum(pre,(char*)pre->pay_packet.packet,pre->payload);
        memcpy((u_char*)pre->packet.packet+(pre->packet.size-pre->tcp_packet.size),pre->tcp_packet.packet,pre->tcp_packet.size);
        int res = pcap_sendpacket(pre->pcap, pre->packet.packet, pre->packet.size);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
        printf("jjjj\n\n");
        return;
    }
  //backward
        u_char * relay_packet = (u_char*)malloc((pre->packet.size));
        backward(relay_packet,pre,type,message);
        int res = pcap_sendpacket(pre->pcap, relay_packet, pre->packet.size);
        printf("dd\n\n");
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
        }
}

int parsing(Prepare* pre){
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet.packet;
    if(ntohs(ethernet->ether_type)!=IPv4){
        fprintf(stderr,"This is not IP Packet\n");
        return 0;
    }
    pre->ether_packet.size = pre->packet.size;
    pre->ether_packet.packet=pre->packet.packet+sizeof(struct libnet_ethernet_hdr);
    printf("ethernet : %u\n\n",pre->ether_packet.size);
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    if(ip->ip_p!=TCP){
        fprintf(stderr,"This is not TCP Packet\n");
        return 0;
    }

    pre->ip_packet.size = pre->ether_packet.size - sizeof(struct libnet_ethernet_hdr);
    printf("ip : %u\n\n",pre->ip_packet.size);
    pre->tcp_packet.packet = pre->ether_packet.packet + ip->ip_hl*5;
    pre->tcp_packet.size = pre->ip_packet.size - ip->ip_hl*5;
    printf("tcp : %u\n\n",pre->tcp_packet.size);
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    pre->pay_packet.packet = pre->tcp_packet.packet+ (tcp->th_off)*4;
    pre->pay_packet.size = pre->tcp_packet.size -(tcp->th_off)*4;
    printf("payload : %u\n\n",pre->pay_packet.size);
    int payload_len = pre->packet.size - sizeof(pre->pay_packet);
    pre->payload = payload_len;
    //printf("%d",payload_len);
    //BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)pre->packet, pat_len);
    if(check_str(pre))/*if data exist*/
    {
       dump(pre->tcp_packet.packet,pre->tcp_packet.size);
       if(!getspace(pre)){//https
           sendPacket(pre,Forward, Rst,NULL);
           sendPacket(pre,Backward, Rst,NULL);
       }
       else{
           sendPacket(pre,Forward, Rst,NULL);
           char* message= "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
           sendPacket(pre,Backward, Fin,message);
       }
    }
    return 1;
}
