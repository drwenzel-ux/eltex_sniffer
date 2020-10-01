#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define N 2048

typedef struct arphdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_char hlen;
  u_char plen;
  u_int16_t oper;
  u_char sha[6];
  u_char spa[4];
  u_char tha[6];
  u_char tpa[4];
} arphdr_t;

void err(const char *m) {
  fprintf(stderr, "err: %s\n", m);
  exit(1);
}

int main(int argc, char *argv[]) {
  int i = 0;
  bpf_u_int32 netaddr = 0, mask = 0;
  struct bpf_program filter;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr = NULL;
  struct pcap_pkthdr pkthdr;
  const unsigned char *packet = NULL;
  arphdr_t *arpheader = NULL;
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);

  if (argc != 2)
    err("arpsniffer <interface>");

  descr = pcap_open_live(argv[1], N, 0, 512, errbuf);
  if (descr == NULL)
    err(errbuf);

  if (pcap_lookupnet(argv[1], &netaddr, &mask, errbuf) == -1)
    err(errbuf);

  if (pcap_compile(descr, &filter, "arp", 1, mask) == -1)
    err(errbuf);

  if (pcap_setfilter(descr, &filter) == -1)
    err(pcap_geterr(descr));

  while (1) {

    if ((packet = pcap_next(descr, &pkthdr)) == NULL)
      err(errbuf);

    arpheader = (struct arphdr *)(packet + 14);

    printf("\n\nreceived packet size: %d bytes\n", pkthdr.len);
    printf("hardware type: %s\n",
           (ntohs(arpheader->htype) == 1) ? "ethernet" : "unknown");
    printf("protocol type: %s\n",
           (ntohs(arpheader->ptype) == 0x0800) ? "ipv4" : "unknown");
    printf("operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)
                                  ? "arp request"
                                  : "arp reply");

    if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
      printf("Sender MAC: ");

      for (i = 0; i < 6; i++)
        printf("%02X:", arpheader->sha[i]);

      printf("\nSender IP: ");

      for (i = 0; i < 4; i++)
        printf("%d.", arpheader->spa[i]);

      printf("\nTarget MAC: ");

      for (i = 0; i < 6; i++)
        printf("%02X:", arpheader->tha[i]);

      printf("\nTarget IP: ");

      for (i = 0; i < 4; i++)
        printf("%d.", arpheader->tpa[i]);

      printf("\n");
    }
  }

  return 0;
}
