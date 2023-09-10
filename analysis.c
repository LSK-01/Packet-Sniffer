#include "analysis.h"
#include "results.h"
#include "sniff.h"
#include "IPArray.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>

#define SIZE_ETHERNET 14
#define IPPROTOCOL_TCP 6

// Linking to variables in sniff.c
extern struct results r;
extern struct IPArray IP;
extern char *blacklist[];
extern int bListVio[BLACKLIST_SIZE];
extern int blacklistCount;

// mutex lock for every analyse function
pthread_mutex_t ARPMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SYNMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t HTTPMutex = PTHREAD_MUTEX_INITIALIZER;

void analyse(unsigned char *packet)
{
  struct ether_header *eth_header = (struct ether_header *)packet;

  // Check if the ethernet header protocol is IP or ARP
  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
  {
    pthread_mutex_lock(&ARPMutex);
    analyseARP(packet);
    pthread_mutex_unlock(&ARPMutex);
  }
  else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
  {
    struct ip *ip = (struct ip *)(packet + SIZE_ETHERNET);
    u_int size_ip = ip->ip_hl * 4;

    // Check if the IP protocol is TCP
    if (ip->ip_p == IPPROTOCOL_TCP)
    {
      struct tcphdr *tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);

      // Checking every control bit in the TCP header for SYN attack
      if (tcp->syn == 1 && tcp->rst == 0 && tcp->ack == 0 && tcp->urg == 0 && tcp->psh == 0 && tcp->fin == 0)
      {
        pthread_mutex_lock(&SYNMutex);
        analyseSYN(tcp, ip);
        pthread_mutex_unlock(&SYNMutex);
      }
      // Check if destination port is port 80, for HTTP traffic
      else if (ntohs(tcp->th_dport) == 80)
      {
        // Get actual packet data - move pointer past all the packet headers
        const char *content = (char *)(packet + SIZE_ETHERNET + size_ip + tcp->doff * 4);

        for (int i = 0; i < BLACKLIST_SIZE; i++)
        {

          if (strstr(content, blacklist[i]) != NULL)
          {
            pthread_mutex_lock(&HTTPMutex);
            analyseHTTP(i, ip);
            pthread_mutex_unlock(&HTTPMutex);
            break;
          }
        }
      }
    }
  }
}

void analyseSYN(struct tcphdr *tcp, struct ip *ip)
{
  r.numSYN++;

  // dereference pointer to array and store ip
  // use ntohl to convert from network to host byte order
  uint32_t ipAddr = ntohl(ip->ip_src.s_addr);

  // check if ipAddr is distinct and increment struct accordingly
  int distinct = isDistinct(IP.IPs, IP.i, ipAddr);
  if (distinct)
  {
    r.distinctIPs++;
    // add to the array
    IP.IPs[IP.i] = ipAddr;
    IP.i++;
  }

  // realloc IP array * 2 if filled up
  if (IP.i == IP.IPSize)
  {
    IP.IPSize *= 2;
    IP.IPs = realloc(IP.IPs, sizeof(uint32_t) * IP.IPSize);
  }
}

void analyseARP(const unsigned char *packet)
{
  struct ether_arp *ether_arp_header = (struct ether_arp *)(packet + SIZE_ETHERNET);

  // Extract the arp opcode, check if it is a reply packet
  if (ntohs(ether_arp_header->arp_op) == ARPOP_REPLY)
  {
    r.numARP++;
  }
}

void analyseHTTP(int i, struct ip *ip)
{
  bListVio[i]++;
  r.blacklistTotal++;
  // inet_ntoa() converts an IP in the form of an in_addr to a dotted decimal notation string
  fprintf(stderr, "==============================\nBlacklisted URL violation detected\nSource IP address: %s\nDestination IP address: %s\n==============================\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
}

int isDistinct(uint32_t *arr, int index, uint32_t address)
{
  int distinct = 1;

  // compare address to every element before it to check if distinct
  for (int i = 0; i < index; i++)
  {
    if (arr[i] == address)
    {
      distinct = 0;
      break;
    }
  }
  return distinct;
}

void destroyMutex()
{
  pthread_mutex_destroy(&ARPMutex);
  pthread_mutex_destroy(&SYNMutex);
  pthread_mutex_destroy(&HTTPMutex);
}