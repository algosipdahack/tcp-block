#include "header.h"
#include "bm.h"
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}
int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    Prepare* pre = (Prepare*)malloc(sizeof(Prepare));
    pre->pcap = pcap;
    Mac my_mac = getMacAddress(argv[1]);
    pre->argv1 = argv[1];
    pre->argv2 = argv[2];
    printf("%s\n",argv[1]);
    printf("%s\n",argv[2]);
    pre->my_mac = my_mac;
    for(int i =0;i <6; i++)
        printf("%x:",my_mac.mac_[i]);
    printf("\n\n");

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        pre->packet.size = header->caplen;
        pre->packet.packet = packet;

        res = parsing(pre);
        if(!res)continue;
    }
    pcap_close(pcap);
    return 0;
}
