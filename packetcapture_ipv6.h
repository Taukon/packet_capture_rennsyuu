#ifndef PACKETCAPTURE_H_
#define PACKETCAPTURE_H_

#include<stdio.h>
#include <string.h>
#include<net/if.h>  ///PF_PACKET
#include <net/ethernet.h> //ETH_P_ALL
#include<netinet/ip.h> //struct iphdr用 (汎用的なstruct ipもある)
#include<netinet/if_ether.h> //struct ether_arp
#include<netinet/tcp.h> //struct tcp
#include<linux/ipv6.h> //ipv6 header
#include <sys/ioctl.h> /* SIOCGIFFLAG SIOCSIFFLAG SIOCGIFINDEX */ 
#include <netpacket/packet.h> //struct sockaddr_ll

int initRawSocket(char *dev);

void analyzePacket(u_char *buf);

void printEtherHeader(u_char *buf);

char *mac_ntoa(u_char *d);

char *ip_ntoa(u_int32_t ip);

void printIPHeader(u_char *buf);

char *ip_ntoa2(u_char *d);

void printArp(u_char *buf);

void printTcpHeader(u_char *buf);

void printIPv6Header(u_char *buf);

#endif