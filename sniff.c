#include "sniff.h"
#include "results.h"
#include "IPArray.h"
#include "queue.h"
#include "dispatch.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define NUMTHREADS 9

struct results r;
struct IPArray IP;

// Queue for threads to pull packets from
// Initialise head and tail to NULL
struct queue packetQueue = {NULL, NULL};
pthread_mutex_t qMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t qCond = PTHREAD_COND_INITIALIZER;
pthread_t tid[NUMTHREADS];
// Used to signal interrupt to threads
int interrupt = 0;

// Blacklist array
char *blacklist[] = {"www.google.co.uk", "www.facebook.com"};
// Number of violations
int bListVio[BLACKLIST_SIZE];

// Public so we can call pcap_close() on the handle
pcap_t *pcap_handle;

// Application main sniffing loop
void sniff(char *interface, int verbose)
{

  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL)
  {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  else
  {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  IP.IPSize = 10;
  IP.IPs = malloc(sizeof(uint32_t) * IP.IPSize);

  // Create the threadpool, entry function being dispatch
  for (int i = 0; i < NUMTHREADS; i++)
  {
    pthread_create(&tid[i], NULL, dispatch, NULL);
  }

  // Listen and wait to handle SIGINT
  signal(SIGINT, handler);

  // Continually sniff packets until pcap_breakloop() called in signal handler
  pcap_loop(pcap_handle, -1, got_packet, NULL);

  // Signal to threads that it is time to exit their infinite loop
  interrupt = 1;
  pthread_cond_broadcast(&qCond);

  // Print results
  printf("\nIntrusion detection report: \n%d SYN packet(s) detected from %d distinct IP(s) (SYN attack)\n%d ARP response(s) (Cache Poisoning)\n%d URL Blacklist violation(s) ", r.numSYN, r.distinctIPs, r.numARP, r.blacklistTotal);

  if (r.blacklistTotal > 0)
  {
    printf("(");
    for (int i = 0; i < BLACKLIST_SIZE; i++)
    {
      if (bListVio[i] > 0)
      {
        printf("%d %s, ", bListVio[i], blacklist[i]);
      }
    }
    printf("\b\b)");
  }
  printf("\n");

  // Rejoin all threads
  for (int i = 0; i < NUMTHREADS; i++)
  {
    pthread_join(tid[i], NULL);
  }

  free(IP.IPs);
  destroy_queue(&packetQueue);
  // Destroy Mutexes
  pthread_mutex_destroy(&qMutex);
  pthread_cond_destroy(&qCond);
  destroyMutex();

  exit(0);
}

// pcap_loop handler function
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  // Add packets to work queue
  pthread_mutex_lock(&qMutex);
  enqueue(&packetQueue, (u_char *)packet);
  pthread_cond_broadcast(&qCond);
  pthread_mutex_unlock(&qMutex);
}

void handler(int signal)
{
  pcap_breakloop(pcap_handle);
  pcap_close(pcap_handle);
}


// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length)
{
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *)data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i)
  {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5)
    {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i)
  {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5)
    {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0)
  {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i)
    {
      if (i < output_bytes)
      {
        printf("%02x ", payload[i]);
      }
      else
      {
        printf("   "); // Maintain padding for partial lines
      }
    }
    printf("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i)
    {
      char byte = payload[i];
      if (byte > 31 && byte < 127)
      {
        // Byte is in printable ascii range
        printf("%c", byte);
      }
      else
      {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
