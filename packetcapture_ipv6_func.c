#include"packetcapture_ipv6.h"

#include<linux/ipv6.h> //ipv6 header

int initRawSocket(char *dev){
	struct ifreq ifr;
	int soc,size;
	struct sockaddr_ll sa;// これがないとbindできない
	soc = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

	//初期化
	memset(&ifr,0,sizeof(struct ifreq));
	strncpy(ifr.ifr_name,dev,sizeof(ifr.ifr_name)-1);

	ioctl(soc,SIOCGIFINDEX,&ifr); //ifrにeth0の情報格納

	sa.sll_family=PF_PACKET;
	sa.sll_protocol=htons(ETH_P_ALL);
	sa.sll_ifindex=ifr.ifr_ifindex;
	bind(soc,(struct sockaddr *)&sa,sizeof(sa));//ifをbind, bindしないとすべてのifが対象
	
	ioctl(soc,SIOCGIFFLAGS,&ifr); //ifrにeth0の情報格納
	ifr.ifr_flags |= IFF_PROMISC ; //promisc オプションを付加
	ioctl(soc,SIOCSIFFLAGS,&ifr); //ifrの情報を設定
	return soc;
}

void analyzePacket(u_char *buf){
    u_char *ptr;
    struct ether_header *eth;
    printEtherHeader(buf);
    struct iphdr *ip_tcp;
    ptr = buf;          //IPHeader探索用
    eth = (struct ether_header*) buf;
    ptr += sizeof(struct ether_header); //IPHeader探索

    
    switch(ntohs(eth->ether_type)){
        case ETH_P_IP:    printf("IP Packet\n");
            printIPHeader(ptr);
            ip_tcp = (struct iphdr*) ptr;       
            if(ip_tcp->protocol == 6){                  //tcpか判定
                ptr += ((struct iphdr*) ptr)->ihl*4;
                printTcpHeader(ptr);
            }
            break;

        case ETH_P_IPV6:    printf("IPv6 Packet\n");
            printIPHeader(ptr);
            break;

        case ETH_P_ARP: printf("ARP Packet\n");
            printArp(ptr);
            break;
            
        default:
            printf("unknown\n");
    }

/*    if(ETH_P_IPV6 == ntohs(eth->ether_type)){
        printf("IPv6 Packet\n");
        printIPHeader(ptr);
    }*/

}

void printEtherHeader(u_char *buf){
    struct ether_header *eth;
    eth = (struct ether_header*) buf;
    printf("----------- ETHERNET -----------\n");
    printf("Dst Mac addr   : %17s \n",mac_ntoa(eth->ether_dhost));
    printf("Src MAC addr   : %17s \n",mac_ntoa(eth->ether_shost));
    printf("Ethernet Type  : 0x%04x\n",ntohs(eth->ether_type));
}

char *mac_ntoa(u_char *d){
    static char str[18];
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",d[0],d[1],d[2],d[3],d[4],d[5]);
    return str;
}

char *ip_ntoa(u_int32_t ip){
    u_char *d = (u_char*) &ip;
    static char str[15];
    sprintf(str, "%d.%d.%d.%d",d[0],d[1],d[2],d[3]);
    return str;
}

void printIPHeader(u_char *buf){
    struct iphdr *ip;
    ip = (struct iphdr*) buf;
    printf("----------- IP -----------\n");
    printf("version=%u\n",ip->version);
    printf("ihl=%u\n",ip->ihl);
    printf("tos=%x\n",ip->tos);
    printf("tot_len=%u\n",ntohs(ip->tot_len));
    printf("id=%u\n",ntohs(ip->id));
    printf("ttl=%u\n",ip->ttl);
    printf("protocol=%u\n",ip->protocol);
    printf("src addr=%s\n",ip_ntoa(ip->saddr));
    printf("dst addr=%s\n",ip_ntoa(ip->daddr));
}

char *ip_ntoa2(u_char *d){
    static char str[15];
    sprintf(str,"%d.%d.%d.%d",d[0],d[1],d[2],d[3]);
    return str;
}

void printArp(u_char *buf){
    struct ether_arp *arp;
    arp =(struct ether_arp *)buf;
    printf("----------- ARP ----------\n");
    printf("arp_hrd=%u\n",ntohs(arp->arp_hrd));
    printf("arp_pro=%u\n",ntohs(arp->arp_pro));
    printf("arp_hln=%u\n",arp->arp_hln);
    printf("arp_pln=%u\n",arp->arp_pln);
    printf("arp_op=%u\n",ntohs(arp->arp_op));
    printf("arp_sha=%s\n",mac_ntoa(arp->arp_sha));
    printf("arp_spa=%s\n",ip_ntoa2(arp->arp_spa));
    printf("arp_tha=%s\n",mac_ntoa(arp->arp_tha));
    printf("arp_tpa=%s\n",ip_ntoa2(arp->arp_tpa));
}

void printTcpHeader(u_char *buf){
    struct tcphdr *ptr;
    ptr = (struct tcphdr *)buf;
    printf("----------- TCP ----------\n");
    printf("src port = %u\n",ntohs(ptr->source));
    printf("dst port = %u\n",ntohs(ptr->dest));
}

void printIPv6Header(u_char *buf){
    struct ipv6hdr *ipv6_test;
    ipv6_test = (struct ipv6hdr*) buf;
    printf("----------- IPv6 ----------\n");
    printf("version=%u\n",ipv6_test->version);
    printf("flow label=%hhn\n",ipv6_test->flow_lbl);
    printf("next header=%u\n",ipv6_test->nexthdr);
    printf("hop limit=%u\n",ipv6_test->hop_limit);
}
