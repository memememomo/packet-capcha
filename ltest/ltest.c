#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

/**
 * @param device      ネットワークインタフェース名
 * @param promiscFlag プロミスキャスモードにするかどうかのフラグ(自分宛以外のパケットも受信するか)
 * @param ipOnly      IPパケットのみを対象とするかどうかのフラグ
 */

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  /**
   * socket関数
   * 第1引数: PF_INET(TCP, UDP), PF_PACKET(データリンク層)
   * 第2引数: SOCK_STREAM(TCP), SOCK_DGRAM(UDP), SOCK_RAW(データリンク層)
   * 第3引数: 0(TCP, UDP), ETH_P_ALL/ETH_P_IP(データリンク層)
   */
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

  /**
   * ioctl関数: ネットワークインタフェース名に対応したインタフェースのインデックスを得る
   */
  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);
  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return(-1);
  }

  /**
   * struct sockaddr_llに「インタフェースインデックス」「プロトコルファミリ」「プロトコル」をセット
   */
  sa.sll_family = PF_PACKET;
  if (ipOnly) {
    sa.sll_protocol = htons(ETH_P_IP);
  }
  else {
    sa.sll_protocol = htons(ETH_P_ALL);
  }
  sa.sll_ifindex = ifreq.ifr_ifindex;

  /**
   * bindでsocにインタフェースを関連付ける
   */
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

    // ビットをONにする
    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;

    if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return(-1);
    }
  }

  return (soc);
}

/**
 * MACアドレスを文字列形式に変換する
 */
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
           hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

  return(buf);
}


int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
  char buf[80];

  fprintf(fp, "ether_header------------------------------\n");
  fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
  fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
  fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
  switch(ntohs(eh->ether_type)) {
  case ETH_P_IP:
    fprintf(fp, "(IP)\n");
    break;
  case ETH_P_IPV6:
    fprintf(fp, "(IPv6)\n");
    break;
  case ETH_P_ARP:
    fprintf(fp, "(ARP)\n");
    break;
  default:
    fprintf(fp, "(unknown)\n");
    break;
  }

  return(0);
}


int main(int argc, char *argv[], char *envp[])
{
  int soc, size;
  u_char buf[2048];
  if (argc <= 1) {
    fprintf(stderr, "ltest device-name\n");
    return(1);
  }

  if ((soc = InitRawSocket(argv[1], 0, 0)) == -1) {
    fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
    return(-1);
  }

  while (1) {

    // readでデータを受信
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    }
    else {
      if (size >= sizeof(struct ether_header)) {
        PrintEtherHeader((struct ether_header *)buf, stdout);
      }
      else {
        fprintf(stderr, "read size(%d) < %d\n", size, sizeof(struct ether_header));
      }
    }
  }

  close(soc);

  return(0);
}
