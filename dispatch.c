#include "dispatch.h"
#include "queue.h"
#include "analysis.h"

#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>

extern struct queue packetQueue;
extern pthread_mutex_t qMutex;
extern pthread_cond_t qCond;
extern int interrupt;

void *dispatch(void * verbose)
{
  while (1)
  {
    // Dequeue packets from global queue variable and run analysis
    pthread_mutex_lock(&qMutex);

    // && !interrupt so that all remaining threads exit instead of waiting at condition
    while (isEmpty(&packetQueue) && !interrupt)
    {
      pthread_cond_wait(&qCond, &qMutex);
    }

    // When interrupt becomes true, exit all threads by releasing the lock and calling pthread_exit()
    if(interrupt){
      pthread_mutex_unlock(&qMutex);
      pthread_exit(0); 
    }

    u_char *packet = packetQueue.head->data;
    int res = dequeue(&packetQueue);
    if(!res){
      fprintf(stderr, "Failed to dequeue packet.\n");
      exit(1);
    }

    pthread_mutex_unlock(&qMutex);

    analyse(packet);
  }
   return NULL;
}