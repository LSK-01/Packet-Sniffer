#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void analyse(unsigned char *packet);
void destroyMutex();
void analyseSYN(struct tcphdr *tcp, struct ip *ip);
int isDistinct(uint32_t *arr, int index, uint32_t address);
void analyseARP(const unsigned char *packet);
void analyseHTTP(int i, struct ip *ip);

#endif
