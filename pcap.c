#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analyze.h"

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  if (ipOnly) {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
      perror("socket");
      return(-1);
    }
  }
  else {
    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
      perror("socket");
      return(-1);
    }
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);
  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return(-1);
  }
  sa.sll_family = PF_PACKET;
  if (ipOnly) {
    sa.sll_protocol = htons(ETH_P_IP);
  }
  else {
    sa.sll_protocol = htons(ETH_P_ALL);
  }
  sa.sll_ifindex = ifreq.ifr_ifindex;
  if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(soc);
    return(-1);
  }

  if (promiscFlag) {
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return(-1);
    }
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
    if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return(-1);
    }
  }

  return(soc);
}


int main(int argc, char *argv[], char *envp[])
{
  int soc, size;
  u_char buf[65535];

  int opt;
  int filter_size = 0;

  while((opt = getopt(argc, argv, "s:")) != -1) {
    switch(opt) {
    case 's':
      filter_size = atoi(optarg);
      break;
    }
  }
  argc = argc - optind;
  argv = argv + optind;

  if (argc <= 0) {
    fprintf(stderr, "pcap device-name\n");
    return(1);
  }

  if ((soc = InitRawSocket(argv[0], 0, 0)) == -1) {
    fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
    return(-1);
  }

  while(1) {
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    }
    else {
      if (size <= filter_size) {
        continue;
      }
      AnalyzePacket(buf, size);
    }
  }

  close(soc);
}
