#include "header.h"
bool check_str(Prepare* pre,char* to_find){
    BmCtx* ctx = BoyerMooreCtxInit((const uint8_t *)to_find, strlen(to_find));
    unsigned char* found = BoyerMoore((uint8_t*)to_find, strlen(to_find), (const uint8_t *)pre->pay_packet.packet, pre->pay_packet.size, ctx);
    if (found == NULL)
        return false;
    return true;
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
void convrt_mac(const char *data, char *cvrt_str, int sz){
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok((char *)data , ":" );
     int temp=0;

     do{
          memset( t_buf, 0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );

     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}

Mac getMacAddress(char* dev){
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0){
       return 0;
    }
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0){
        close(sock);
        return 0;
    }
    convrt_mac(ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr)-1);
    close(sock);
    return Mac(mac_adr);
}
