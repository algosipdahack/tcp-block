#include "header.h"
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
