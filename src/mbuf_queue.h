#ifndef MBUF_QUEUE_H
#define MBUF_QUEUE_H

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>

struct mbuf_queue {  
  uint16_t len;
  uint16_t max;
	struct rte_mbuf *queue[0];
};

struct mbuf_queues {  
  uint16_t len;
	struct mbuf_queue* queue[0];
};

struct mbuf_queue*
create_mbuf_queue(uint16_t len);

struct mbuf_queues*
create_mbuf_queues(uint8_t size, uint16_t len);

void
destroy_mbuf_queue(struct mbuf_queue *queue);

void
destroy_mbuf_queues(struct mbuf_queues *queues);

#endif
