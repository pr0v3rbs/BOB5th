send-arp: send-arp.o InitPcap.o GetNetworkInfo.o
	gcc -o send-arp send-arp.o InitPcap.o GetNetworkInfo.o -lpcap

send-arp.o: send-arp.c
	gcc -c -o send-arp.o send-arp.c -lpcap

InitPcap.o: InitPcap.c
	gcc -c -o InitPcap.o InitPcap.c -lpcap

GetNetworkInfo.o:
	gcc -c -o GetNetworkInfo.o GetNetworkInfo.c

clean:
	rm send-arp send-arp.o InitPcap.o GetNetworkInfo.o
