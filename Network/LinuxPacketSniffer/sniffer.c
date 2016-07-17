#include <stdio.h>
#include <pcap.h>

typedef enum {PROT_UNKNOWN, PROT_TCP, PROT_UDP, } Protocol;

struct Packet
{
    char srcMAC[18];
    char dstMAC[18];
    char srcIP[16];
    char dstIP[16];
    unsigned short srcPORT;
    unsigned short dstPORT;
};

int ConvertByteToTCP(const u_char* packet, struct Packet* tcp)
{
    Protocol result = PROT_UNKNOWN;
    if (packet[12] == 0x08 && packet[13] == 0x00 && // Ethernet header type : IPv4
        packet[23] == 0x06) // IPv4 header protocol : TCP
    {
        snprintf(tcp->srcMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            packet[6],packet[7],packet[8],packet[9],packet[10],packet[11],packet[12]);
        snprintf(tcp->dstMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);

        snprintf(tcp->srcIP, 16, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
        snprintf(tcp->dstIP, 16, "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);

        tcp->srcPORT = ntohs(*((unsigned short*)(&packet[34])));
        tcp->dstPORT = ntohs(*((unsigned short*)(&packet[36])));

        result = PROT_TCP;
    }

    return result;
}

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct Packet tcp;
    if (ConvertByteToTCP(packet, &tcp) == PROT_TCP)
    {
        printf("src MAC  %s, dst MAC  %s\n", tcp.srcMAC, tcp.dstMAC);
        printf("src IP   %s, dst IP   %s\n", tcp.srcIP, tcp.dstIP);
        printf("src PORT %d, dst PORT %d\n", tcp.srcPORT, tcp.dstPORT);
        puts("");
    }
}

int main()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char filter_exp[] = "";
    pcap_t *handle;
    struct bpf_program fp;
    const u_char *packet;
    struct pcap_pkthdr header;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "lookupdev error: %s\n", errbuf);
        return 0;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Get netmask fail: %s\n", errbuf);
        return 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "open_live error: %s\n", errbuf);
        return 0;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "compile error: %s\n", pcap_geterr(handle));
        return 0;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "serfilter error: %s\n", pcap_geterr(handle));
        return 0;
    }

    pcap_loop(handle, 0, (pcap_handler)PacketCallback, NULL);
    pcap_close(handle);

    return 0;
}
