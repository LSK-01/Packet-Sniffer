#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H
#include <pcap.h>

#define BLACKLIST_SIZE 2

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
void handler(int signal);
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
