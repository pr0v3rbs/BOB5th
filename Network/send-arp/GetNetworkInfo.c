#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "GetNetworkInfo.h"

BYTE ConvertStrToByte(char c1, char c2)
{
    BYTE numHigh, numLow;

    if ('0' <= c1 && c1 <= '9')
        numHigh = c1 - '0';
    else
        numHigh = c1 - 'a' + 10;

    if ('0' <= c2 && c2 <= '9')
        numLow = c2 - '0';
    else
        numLow = c2 - 'a' + 10;

    return (numHigh << 4) + numLow;
}

int ConvertAddrToByteIP(/*in*/ char* addr, /*out*/ BYTE* ip)
{
    int result = 0;
    struct in_addr structAddr;

    if (result = inet_aton(addr, &structAddr))
    {
        ip[3] = (structAddr.s_addr & 0xff000000) >> 24;
        ip[2] = (structAddr.s_addr & 0x00ff0000) >> 16;
        ip[1] = (structAddr.s_addr & 0x0000ff00) >> 8;
        ip[0] = (structAddr.s_addr & 0x000000ff);
    }

    return result;
}

int GetLocalMacAddress(/*out*/ BYTE* mac)
{
    int result = 0;
    FILE* fp;
    char command[50] = "ifconfig > ifconfig_result";
    char* line;
    size_t len;

    if (system(command) == 0)
    {
        if (fp = fopen("ifconfig_result", "r"))
        {
            while (getline(&line, &len, fp) != -1)
            {
                // need to check connected ethernet
                if (strstr(line, "ether"))
                {
                    char* token;
                    token = strtok(line, " ");
                    token = strtok(NULL, " ");
                    mac[0] = ConvertStrToByte(token[0], token[1]);
                    mac[1] = ConvertStrToByte(token[3], token[4]);
                    mac[2] = ConvertStrToByte(token[6], token[7]);
                    mac[3] = ConvertStrToByte(token[9], token[10]);
                    mac[4] = ConvertStrToByte(token[12], token[13]);
                    mac[5] = ConvertStrToByte(token[15], token[16]);
                    result = 1;
                    remove("ifconfig_result");
                    break;
                }
            }
        }
    }

    return result;
}

int GetMacAddress(/*in*/ char* ipStr, /*out*/ BYTE* mac)
{
    int result = 0;
    FILE* fp;
    char command[50] = "arping ";
    char data[200];

    strcat(command, ipStr);
    strcat(command, " -c 1 > arping_result");

    if (system(command) == 0)
    {
        fp = fopen("arping_result", "r");
        if (fp && fread(data, 200, 1, fp) > 0 && !strstr(data, "Timeout"))
        {
            char* token;
            token = strtok(data, "\n");
            token = strtok(NULL, "\n");
            token = strtok(token, " ");
            token = strtok(NULL, " ");
            token = strtok(NULL, " ");
            token = strtok(NULL, " ");
            mac[0] = ConvertStrToByte(token[0], token[1]);
            mac[1] = ConvertStrToByte(token[3], token[4]);
            mac[2] = ConvertStrToByte(token[6], token[7]);
            mac[3] = ConvertStrToByte(token[9], token[10]);
            mac[4] = ConvertStrToByte(token[12], token[13]);
            mac[5] = ConvertStrToByte(token[15], token[16]);
            remove("arping_result");
            result = 1;
        }
    }

    return result;
}

int GetGatewayIP(/*out*/ BYTE* ip)
{
    int result = 0;
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    char temIP[20];

    if (system("arp -a > arp_table") == 0)
    {
        if (fp = fopen("arp_table", "r"))
        {
            while (getline(&line, &len, fp) != -1)
            {
                if (strstr(line, "gateway"))
                {
                    int ipStrIdx = 0;
                    for (int i = 9; line[i] != ')'; i++)
                    {
                        temIP[ipStrIdx++] = line[i];
                    }
                    temIP[ipStrIdx] = '\0';

                    if (ConvertAddrToByteIP(temIP, ip))
                    {
                        result = 1;
                    }
                    break;
                }
            }
            remove("arp_table");
        }
    }

    return result;
}
