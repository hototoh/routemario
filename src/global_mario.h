/**
 * global_mario.h: 
 * declare global RouteMario's variables.
 */

#ifndef ROUTEMARIO_H
#define ROUTEMARIO_H

#include "interfaces.h"
#include "mbuf_queue.h"
#include "eth.h"
#include "ipv4.h"
#include "arp.h"

/* eth.h */
RTE_DECLARE_PER_LCORE(uint16_t, nic_queue_id);
RTE_DECLARE_PER_LCORE(struct mbuf_queue **, eth_tx_queue);
extern struct fdb_table *fdb_tb;

/* ipv4.h */
RTE_DECLARE_PER_LCORE(struct mbuf_queue *, routing_queue);

/* interfaces.h */
extern struct l3_interfaces *intfs;

/* arp.h */
extern struct arp_table *arp_tb;


/* fib.h */
// extern ;

#endif
