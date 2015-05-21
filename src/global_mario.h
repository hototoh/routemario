/**
 * global_mario.h: 
 * declare global RouteMario's variables.
 */

#ifndef ROUTEMARIO_H
#define ROUTEMARIO_H

#include <rte_lpm.h>
#include <rte_lcore.h>

#include "interfaces.h"
#include "mbuf_queue.h"
#include "eth.h"
#include "ipv4.h"
#include "arp.h"

extern struct rte_mempool *rmario_pktmbuf_pool;
extern uint8_t _mid;
/* eth.h */
RTE_DECLARE_PER_LCORE(uint16_t, nic_queue_id);
static inline uint16_t
get_nic_queue_id() {
  return RTE_PER_LCORE(nic_queue_id);
}

static inline void
set_nic_queue_id(uint16_t queue_id) {
  RTE_PER_LCORE(nic_queue_id) = queue_id;
}

RTE_DECLARE_PER_LCORE(struct mbuf_queues *, eth_tx_queue);
static inline struct mbuf_queues*
get_eth_tx_Qs() {
  return RTE_PER_LCORE(eth_tx_queue);
}

static inline struct mbuf_queues*
set_eth_tx_Qs(struct mbuf_queues* queue) {
  RTE_PER_LCORE(eth_tx_queue) = queue;
}

static inline struct mbuf_queue*
get_eth_tx_Q(uint8_t port_id) {
  return (RTE_PER_LCORE(eth_tx_queue)->queue)[port_id];
}
extern struct fdb_table *fdb_tb;

/* ipv4.h */
RTE_DECLARE_PER_LCORE(struct mbuf_queue *, routing_queue);
static inline struct mbuf_queue*
get_routing_Q() {
  unsigned core_id = rte_lcore_id();
  return RTE_PER_LCORE(routing_queue);
}

static inline void
set_routing_Q(struct mbuf_queue *q) {
  RTE_PER_LCORE(routing_queue) = q;
}

/* interfaces.h */
extern struct l3_interfaces *intfs;

/* arp.h */
extern struct arp_table *arp_tb;

/* fib for tmp */
extern struct rte_lpm* rib; /* defined in mario_config.c */
extern uint32_t next_hop_tb[255]; /* defined in mario_config.c */
#endif
