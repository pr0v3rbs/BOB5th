#include <stdio.h>
#include <pcap.h>
#include "InitPcap.h"

int InitPcap(pcap_t **handle)
{
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int result = 0; // need to constant
    char dev[] = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(dev, &net, &mask, errbuf) != -1)
    {
        *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (*handle)
        {
            result = 1;
        }
        else
        {
            fprintf(stderr, "open_live error: %s\n", errbuf);
        }
    }
    else
    {
        fprintf(stderr, "Get netmask fail: %s\n", errbuf);
    }

    return result;
}
