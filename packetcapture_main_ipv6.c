#include"packetcapture_ipv6.h"


int main(){
    int soc;
    u_char buf[65535];
    soc = initRawSocket("eth0");
    while(1){
        read(soc, buf, sizeof(buf));
        analyzePacket(buf);
    }
}
