#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include "header.h"
#include "bm.h"

BmCtx* ctx;
int check_str(Prepare* pre){
    uint32_t txt_len = pre->pay_packet.size;
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
    uint32_t txt_len = pre->pay_packet.size;
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
u_short compute_tcp_checksum(Prepare *pre) {
    register unsigned long sum = 0;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    unsigned short tcpLen = ntohs(ip->ip_len) - (ip->ip_hl<<2);
    //add the pseudo header
    //the source ip
    sum += (ip->ip_src.s_addr>>16)&0xFFFF;
    sum += (ip->ip_src.s_addr)&0xFFFF;
    //the dest ip
    sum += (ip->ip_dst.s_addr>>16)&0xFFFF;
    sum += (ip->ip_dst.s_addr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;
    tcp->th_sum = 0;
    while (tcpLen > 1) {
        sum += * pre->tcp_packet.packet++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*pre->tcp_packet.packet)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
   return (unsigned short)sum;
}
u_short TcpCheckSum(Prepare* pre)
{
    print(pre);
    PSD_HEADER psd_header;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;

    tcp->th_sum=0;
    print(pre);
    psd_header.m_daddr.s_addr=ip->ip_dst.s_addr;
    printf("m_daddr: %x\n\n",ntohl(ip->ip_dst.s_addr));
    psd_header.m_saddr.s_addr=ip->ip_src.s_addr;
    printf("m_sddr: %x\n\n",ntohl(ip->ip_src.s_addr));
    psd_header.m_mbz=0;
    printf("m_mbz: %x\n\n",psd_header.m_mbz);
    psd_header.m_ptcl=IPPROTO_TCP;
    printf("m_ptcl: %x\n\n",psd_header.m_ptcl);
    psd_header.m_tcpl=htons(pre->pay_packet.size);
    printf("m_tcpl: %u\n\n",pre->pay_packet.size);
    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER));
    memcpy(tcpBuf+sizeof(PSD_HEADER),pre->tcp_packet.packet,pre->tcp_packet.size);
    return CheckSum((u_short *)tcpBuf,sizeof(PSD_HEADER)+pre->tcp_packet.size);
}
void backward(u_char * relay_packet, Prepare* pre,BlockType type,Direction direction,char* message){
    memcpy(&relay_packet,pre->packet.packet,pre->packet.size);
    struct libnet_ethernet_hdr* ethernet=(struct libnet_ethernet_hdr*)pre->packet.packet;

    //change mac
    ethernet->ether_shost = pre->my_mac;
    if(direction==Backward){
        ethernet->ether_dhost = ethernet->ether_shost;
    }
    for(int i =0;i <6; i++)
        printf("%x:",ethernet->ether_dhost.mac_[i]);
    printf("\n\n");
    for(int i =0;i <6; i++)
        printf("%x:",ethernet->ether_shost.mac_[i]);
    printf("\n\n");

    //printf("%x",pre->ether_packet.size);
    memcpy(&relay_packet,ethernet,pre->ether_packet.size);
    relay_packet+=sizeof(struct libnet_ethernet_hdr);
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pre->ether_packet.packet;
    if(direction==Backward){
        //change ip
        in_addr_t ip_src = ip->ip_src.s_addr;
        ip->ip_src.s_addr = ip->ip_dst.s_addr;
        ip->ip_dst.s_addr = ip_src;
    }

    //cal ip_checksum
    char ipBuf[65536];
    memcpy(ipBuf,&relay_packet,sizeof(struct libnet_ipv4_hdr));
    ip->ip_sum = CheckSum((u_short *)ipBuf,pre->ip_packet.size);
    //printf("%x",pre->ip_packet.size);
    memcpy(&relay_packet,ip,pre->ip_packet.size);

    printf("sip : %x\n\n",ip->ip_src.s_addr);
    printf("dip : %x\n\n",ip->ip_dst.s_addr);

    //cal tcp_checksum
    relay_packet += ((struct libnet_ipv4_hdr*)pre->ether_packet.packet)->ip_hl*5;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)pre->tcp_packet.packet;

    tcp->th_flags = type; //rst or fin
    printf("flag: %x\n\n",tcp->th_flags);
    //check checksum
    tcp->th_sum = compute_tcp_checksum(pre);
    printf("<<%x>>\n\n",tcp->th_sum);
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
void print(Prepare(*pre)){
    printf("=========================\n");
    printf("ip : %u\n\n",pre->ether_packet.size);
    printf("tcp : %u\n\n",pre->tcp_packet.size);
    printf("payload : %u\n\n",pre->pay_packet.size);
    printf("=========================\n");
}
void sendPacket(Prepare* pre,Direction direction,BlockType type,char* message){
    u_char * relay_packet = (u_char*)malloc((pre->packet.size));
    backward(relay_packet,pre,type,direction,message);
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
    //printf("%d",payload_len);
    //BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)pre->packet, pat_len);
    if(check_str(pre))/*if data exist*/
    {
       dump(pre->tcp_packet.packet,pre->tcp_packet.size);
       if(!getspace(pre)){//https
           Prepare*pro1 = pre;
           sendPacket(pro1,Forward, Rst,NULL);
           Prepare*pro2 = pre;
           sendPacket(pro2,Backward, Rst,NULL);
       }
       else{
           Prepare*pro1 = pre;
           sendPacket(pro1,Forward, Rst,NULL);
           Prepare*pro2 = pre;
           char* message= "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
           sendPacket(pro2,Backward, Fin,message);
       }
    }
    return 1;
}
