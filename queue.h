
struct element
{
    struct element *next;
    unsigned char* data;
};
struct queue
{
    struct element *head;
    struct element *tail;
};

void enqueue(struct queue *queue, unsigned char* val);
int isEmpty(struct queue *queue);
int dequeue(struct queue* queue);
void destroy_queue(struct queue *q);

