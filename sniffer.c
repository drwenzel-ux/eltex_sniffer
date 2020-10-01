#include <ctype.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define N 2048

void err(const char *m) {
  fprintf(stderr, "err: %s\n", m);
  exit(1);
}

void process(u_char *arg, const struct pcap_pkthdr *pkthdr,
             const u_char *packet) {

  int i = 0;
  int *counter = (int *)arg;

  printf("packet count: %d\n", ++(*counter));
  printf("received packet size: %d\n", pkthdr->len);
  printf("payload:\n");

  for (i = 0; i < pkthdr->len; i++) {
    if (isprint(packet[i]))
      printf("%c ", packet[i]);
    else
      printf(". ");

    if ((i % 10 == 0 && i != 0) || i == pkthdr->len - 1)
      printf("\n");
  }
  return;
}

int main(int argc, char *argv[]) {
  int count;
  pcap_t *descr;
  pcap_if_t *alldevices;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevices, errbuf) == PCAP_ERROR)
    err("pcap_findalldevs failed!");

  printf("Opening device %s\n", alldevices->name);

  descr = pcap_open_live(alldevices->name, N, 1, 512, errbuf);
  if (descr == NULL)
    err(errbuf);

  if (pcap_loop(descr, -1, process, (u_char *)&count) == -1)
    err(pcap_geterr(descr));

  return 0;
}
