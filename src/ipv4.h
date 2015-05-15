#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>


RTE_DECLARE_PER_LCORE(struct mbuf_queue, routing_queue);

static inline struct mbuf_queue*
get_mbuf_queue() {
  return &RTE_PER_LCORE(routing_queue);
}

void
ip_rcv(struct rte_mbuf **buf, uint16_t n_rx);

int
ip_send(struct rte_mbuf *buf);

/* when buf is not NULL, reuse the buffer. */
void
ip_output(uint32_t dst, uint32_t src, struct rte_mbuf* buf);

int
ip_enqueue_routing_pkt(struct mbuf_queue* routing_queue, struct mbuf* buf);


#endif
