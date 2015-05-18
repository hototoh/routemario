/**
 * global_mario.h: 
 * declare global RouteMario's variables.
 */

#ifndef ROUTEMARIO_H
#define ROUTEMARIO_H

#include <rte_lpm.h>

#include "interfaces.h"
#include "mbuf_queue.h"
#include "eth.h"
#include "ipv4.h"
#include "arp.h"

/* eth.h */
RTE_DECLARE_PER_LCORE(uint16_t, nic_queue_id);
RTE_DECLARE_PER_LCORE(struct mbuf_queue **, eth_tx_queue);
static inline struct mbuf_queue**
get_eth_tx_Qs() {
  return RTE_PER_LCORE(eth_tx_queue);
}

static inline struct mbuf_queue*
get_eth_tx_Q(uint8_t port_id) {
  return (RTE_PER_LCORE(eth_tx_queue))[port_id];
}

static inline uint16_t
get_nic_queue_id() {
  return RTE_PER_LCORE(nic_queue_id);
}

static inline void
set_nic_queue_id(uint16_t queue_id) {
  RTE_PER_LCORE(nic_queue_id) = queue_id;
}
extern struct fdb_table *fdb_tb;

/* ipv4.h */
RTE_DECLARE_PER_LCORE(struct mbuf_queue *, routing_queue);
static inline struct mbuf_queue*
get_routing_Q() {
  return RTE_PER_LCORE(routing_queue);
}

/* interfaces.h */
extern struct l3_interfaces *intfs = NULL;

/* arp.h */
extern struct arp_table *arp_tb = NULL;


/* fib for tmp */
extern struct rte_lpm* rib = NULL;
extern uint32_t next_hop_tb[255]; /* defined in mario_config.h */
#endif
