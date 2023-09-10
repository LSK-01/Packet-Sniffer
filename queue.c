#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "queue.h"

#define BUFSIZE 100

// enqueue at tail
void enqueue(struct queue *queue, u_char * val)
{
    struct element *node = malloc(sizeof(struct element));
    node->data = val;
    node->next = NULL;

    if (isEmpty(queue))
    {
        // set node as both head and tail
        queue->head = node;
        queue->tail = node;
    }
    else
    {
        queue->tail->next = node;
        queue->tail = node;
    }
}

void destroy_queue(struct queue *queue)
{ // destroys the queue and frees the memory
    while (!isEmpty(queue))
    {
        dequeue(queue);
    }
}

int isEmpty(struct queue *queue)
{ // checks if queue is empty
    return (queue->head == NULL);
}

int dequeue(struct queue *queue)
{
    if (isEmpty(queue))
    {
        return 0;
    }
    else
    {
        struct element *temp = queue->head;
        queue->head = queue->head->next;
        // we only had one element enqueued, and now we've dequeued it, so set tail to null as well
        if (queue->head == NULL)
        {
            queue->tail = NULL;
        }

        temp->next = NULL;
        free(temp);

        return 1;
    }
}