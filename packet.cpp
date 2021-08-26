#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "header.h"
#include "bm.h"


u_short CheckSum(u_short *buffer, int size)
{
    dump((u_char*)buffer,sizeof(struct libnet_ipv4_hdr));
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

void forward(Prepare*pre, ether_ip_tcp* send_packet)
{
    printf("<<FORWARD>>\n\n");
    pre->packet.size -=pre->pay_packet.size;
    send_packet = (ether_ip_tcp*)malloc(sizeof(ether_ip_tcp));
    //ethernet
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->ether_packet.packet;
    memcpy(&(send_packet->ethernet),ethernet,sizeof(struct libnet_ethernet_hdr));

    printf("%u\n\n",sizeof(struct libnet_ethernet_hdr));
    send_packet->ethernet.ether_shost = pre->my_mac;

    //ip
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ip_packet.packet;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    printf("<<IP>>\n");
    memcpy(&(send_packet->ip),pre->ip_packet.packet,(((struct libnet_ipv4_hdr*)pre->ip_packet.packet)->ip_hl*4));
    dump((u_char*)send_packet,sizeof(ether_ip_tcp));
    send_packet->ip.ip_len = htons(ip->ip_hl*4+tcp->th_off*4);

    send_packet->ip.ip_sum = 0;
    char ipBuf[65535];
    memcpy(ipBuf,&send_packet->ip,sizeof(struct libnet_ipv4_hdr));
    send_packet->ip.ip_sum = CheckSum((u_short *)ipBuf,sizeof(struct libnet_ipv4_hdr));
    printf("m_tcpl ip: %x\n\n",send_packet->ip.ip_sum);

    memcpy(&(send_packet->tcp),pre->tcp_packet.packet,(tcp->th_off)*4);
    send_packet->tcp.th_flags = Rst;
    send_packet->tcp.th_sum = 0;

    PSD_HEADER psd_header;
    psd_header.m_daddr.s_addr=send_packet->ip.ip_dst.s_addr;
    psd_header.m_saddr.s_addr=send_packet->ip.ip_src.s_addr;
    psd_header.m_mbz=0;
    psd_header.m_ptcl=IPPROTO_TCP;
    psd_header.m_tcpl=htons(send_packet->tcp.th_off*4);

    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER));
    memcpy(tcpBuf+sizeof(PSD_HEADER),&send_packet->tcp,send_packet->tcp.th_off*4);

    send_packet->tcp.th_sum = CheckSum((u_short *)tcpBuf,sizeof(PSD_HEADER)+send_packet->tcp.th_off*4);
    printf("checksum : %x\n\n",send_packet->tcp.th_sum);
    dump((u_char*)pre->packet.packet,sizeof(ether_ip_tcp));
    dump((u_char*)send_packet,sizeof(ether_ip_tcp));
}

void backward(Prepare*pre, ether_ip_tcp_pay* send_packet,char*message)
{
    printf("<<BACKWARD>>\n\n");
    send_packet = (ether_ip_tcp_pay*)malloc(sizeof(struct ether_ip_tcp)+strlen(message));
    pre->packet.size = pre->packet.size - pre->pay_packet.size + strlen(message);

    //ethernet
    pre->ether_packet.size += strlen(message);
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->ether_packet.packet;
    memcpy(&(send_packet->ethernet),pre->ether_packet.packet,sizeof(struct libnet_ethernet_hdr));
    send_packet->ethernet.ether_dhost = send_packet->ethernet.ether_dhost;
    send_packet->ethernet.ether_shost = pre->my_mac;
    //ip
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ip_packet.packet;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    pre->ip_packet.size += strlen(message);
    memcpy(&(send_packet->ip),pre->ip_packet.packet,(((struct libnet_ipv4_hdr*)pre->ip_packet.packet)->ip_hl*4));
    dump((u_char*)send_packet,sizeof(struct ether_ip_tcp)+strlen(message));
    send_packet->ip.ip_ttl = 128;
    send_packet->ip.ip_len = htons(ip->ip_hl*4+tcp->th_off*4+ strlen(message));

    struct in_addr tmp = send_packet->ip.ip_src;
    send_packet->ip.ip_src = send_packet->ip.ip_dst;
    send_packet->ip.ip_dst = tmp;

    send_packet->ip.ip_sum = 0;
    char ipBuf[65535];
    memcpy(ipBuf,&send_packet->ip,sizeof(struct libnet_ipv4_hdr));
    send_packet->ip.ip_sum = CheckSum((u_short *)ipBuf,sizeof(struct libnet_ipv4_hdr));
    printf("m_tcpl ip: %x\n\n",send_packet->ip.ip_sum);
    dump((u_char*)send_packet,sizeof(struct ether_ip_tcp)+strlen(message));

    //tcp
    pre->tcp_packet.size += strlen(message);
    memcpy(&(send_packet->tcp),pre->tcp_packet.packet,(tcp->th_off)*4);
    u_int16_t tmp_p = send_packet->tcp.th_dport;
    send_packet->tcp.th_dport = send_packet->tcp.th_sport;
    send_packet->tcp.th_sport = tmp_p;

    send_packet->tcp.th_seq += strlen(message);
    u_int32_t tmp_s = send_packet->tcp.th_seq;
    send_packet->tcp.th_seq = send_packet->tcp.th_ack;
    send_packet->tcp.th_ack = tmp_s;

    send_packet->tcp.th_flags = Fin;
    send_packet->tcp.th_sum = 0;

    PSD_HEADER psd_header;
    psd_header.m_daddr.s_addr=send_packet->ip.ip_dst.s_addr;
    psd_header.m_saddr.s_addr=send_packet->ip.ip_src.s_addr;
    psd_header.m_mbz=0;
    psd_header.m_ptcl=IPPROTO_TCP;
    psd_header.m_tcpl=htons(send_packet->tcp.th_off*4);

    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER));
    memcpy(tcpBuf+sizeof(PSD_HEADER),&send_packet->tcp,send_packet->tcp.th_off*4);

    send_packet->tcp.th_sum = CheckSum((u_short *)tcpBuf,sizeof(PSD_HEADER)+send_packet->tcp.th_off*4);
    printf("checksum : %x\n\n",send_packet->tcp.th_sum);

    //payload
    memcpy(send_packet->pay.data,message,strlen(message));
    dump((u_char*)pre->packet.packet,sizeof(struct ether_ip_tcp)+strlen(message));
    dump((u_char*)send_packet,sizeof(struct ether_ip_tcp)+strlen(message));
}

void print(Prepare(*pre))
{
    printf("=========================\n");
    printf("ip : %u\n\n",pre->ether_packet.size);
    printf("tcp : %u\n\n",pre->tcp_packet.size);
    printf("payload : %u\n\n",pre->pay_packet.size);
    printf("=========================\n");
}

void sendPacket(Prepare* pre,Direction dir, char* message)
{
    int res;
    if(dir==Forward){
        ether_ip_tcp* send_packet;
        forward(pre,send_packet);
        res = pcap_sendpacket(pre->pcap, (u_char*)send_packet, sizeof(ether_ip_tcp));
    }else{
        ether_ip_tcp_pay* send_packet2;
        backward(pre,send_packet2,message);
        res = pcap_sendpacket(pre->pcap, (u_char*)send_packet2, sizeof(struct ether_ip_tcp)+strlen(message));
    }
    printf("dd\n\n");
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pre->pcap));
    }
}

void printpacket(Prepare*pre)
{
    printf("ethernet : %u\n\n",pre->ether_packet.size);
    printf("ip : %u\n\n",pre->ip_packet.size);
    printf("tcp : %u\n\n",pre->tcp_packet.size);
    printf("payload : %u\n\n",pre->pay_packet.size);
}

int parsing(Prepare* pre)
{
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet.packet;
    if(ntohs(ethernet->ether_type)!=IPv4){
        fprintf(stderr,"This is not IP Packet\n");
        return 0;
    }
    //ethernet
    pre->ether_packet.size = pre->packet.size;
    pre->ether_packet.packet= pre->packet.packet;

    //ip
    pre->ip_packet.packet = pre->packet.packet+sizeof(struct libnet_ethernet_hdr);
    pre->ip_packet.size = pre->ether_packet.size - sizeof(struct libnet_ethernet_hdr);
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ip_packet.packet;
    if(ip->ip_p!=TCP){
        fprintf(stderr,"This is not TCP Packet\n");
        return 0;
    }

    //tcp
    pre->tcp_packet.packet = pre->ip_packet.packet + ip->ip_hl*4;
    pre->tcp_packet.size = pre->ip_packet.size - ip->ip_hl*4;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    tcp->th_off = 5; //option out
    //payload
    pre->pay_packet.packet = pre->tcp_packet.packet+ (tcp->th_off)*4;
    pre->pay_packet.size = pre->tcp_packet.size -(tcp->th_off)*4;


    pre->ether_packet.size -= pre->pay_packet.size;
    pre->ip_packet.size = ip->ip_hl*4+(tcp->th_off)*4;
    pre->tcp_packet.size = (tcp->th_off)*4;
    printpacket(pre);
    if(check_str(pre,pre->argv2))/*if data exist*/
    {
       if(check_str(pre,"GET ")){//http
           Prepare*pro1 = pre;
           sendPacket(pro1,Forward,NULL);
           Prepare*pro2 = pre;
           char* message= "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
           sendPacket(pro2,Backward,message);
       }
    }
    return 1;
}
