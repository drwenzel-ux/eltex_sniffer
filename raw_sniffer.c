#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile sig_atomic_t stop;

void sigint_handler(int sig) { stop = 1; }

void err(const char *m) {
  perror(m);
  exit(1);
}

void print_mac(const char *m, unsigned char *addr) {
  printf("%s: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", m, addr[0], addr[1], addr[2],
         addr[3], addr[4], addr[5]);
}

int set_handler(void *handler, int signum, int flags) {
  int retval;
  struct sigaction sa;

  sa.sa_handler = handler;
  sa.sa_flags = flags;
  sigemptyset(&sa.sa_mask);

  retval = sigaction(signum, &sa, 0);

  return retval;
}

int main(int argc, char const *argv[]) {
  int fd;
  ssize_t numbyte;
  size_t offset;
  size_t frame_size;
  unsigned char *frame;

  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  struct protoent *nproto;
  struct in_addr src, dst;

  /* set handler ctrl^c */
  set_handler(sigint_handler, SIGINT, SA_RESTART);

  frame_size = sizeof(*eth_header) + sizeof(*ip_header) + sizeof(*tcp_header);
  frame = calloc(frame_size, __CHAR_BIT__);

  fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (fd == -1)
    err("socket failed");

  for (;;) {
    offset = 0;

    if (stop)
      break;

    numbyte = recv(fd, frame, frame_size, 0);

    if (numbyte == -1) {
      perror("recv return -1");
      continue;
    }

    printf("\nreceive %ld byte:\n", numbyte);

    /* link layer */
    eth_header = (struct ethhdr *)frame;
    print_mac("source mac", eth_header->h_source);
    print_mac("dest mac", eth_header->h_source);
    nproto = getprotobynumber((int)eth_header->h_proto);
    printf("protocol: %s\n", nproto->p_name);

    offset += sizeof(*eth_header);

    /* network layer */
    ip_header = (struct iphdr *)(frame + offset);
    src.s_addr = ip_header->saddr;
    dst.s_addr = ip_header->daddr;
    printf("source ip: %s\n", inet_ntoa(src));
    printf("dest ip: %s\n", inet_ntoa(dst));
    nproto = getprotobynumber(ip_header->protocol);
    printf("protocol : %s\n", nproto->p_name);

    offset += sizeof(*ip_header);

    /* transport layer */
    switch (ip_header->protocol) {
    case IPPROTO_TCP:
      tcp_header = (struct tcphdr *)(frame + offset);
      printf("source port: %d\n", ntohs(tcp_header->source));
      printf("dest port: %d\n", ntohs(tcp_header->dest));
      break;

    case IPPROTO_UDP:
      udp_header = (struct udphdr *)(frame + offset);
      printf("source port: %d\n", ntohs(udp_header->source));
      printf("dest port: %d\n", ntohs(udp_header->dest));
      break;

    default:
      break;
    }
  }

  free(frame);
  close(fd);
  return 0;
}
