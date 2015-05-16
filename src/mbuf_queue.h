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

struct mbuf_queue*
create_mbuf_queue(uint16_t len);

void
destroy_mbuf_queue(struct mbuf_queue *queue);

#endif
