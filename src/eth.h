#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#include "mbuf_queue.h"

#define MAX_PKT_BURST 32
#define MAX_PORT 4

RTE_DECLARE_PER_LCORE(struct mbuf_queue*, eth_tx_queue);
RTE_DECLARE_PER_LCORE(uint16_t, nic_queue_id);

static inline struct mbuf_queue*
get_eth_tx_Q() {
  return RTE_PER_LCORE(eth_tx_queue);
}

static inline struct mbuf_queue*
get_nic_queue_id() {
  return RTE_PER_LCORE(nic_queue_id);
}

static inline struct mbuf_queue*
set_nic_queue_id(uint16_t queue_id) {
  RTE_PER_LCORE(nic_queue_id) = queue_id;
}

int
eth_input(struct rte_mbuf** bufs, uint16_t n_rx, uint8_t src_port);

/* this function is called from upper layer function */
void
eth_enqueue_tx_pkt(struct rte_mbuf *buf);

/* this function is called from main loop function */
void
eth_queue_xmit(uint8_t dst_port, uint16_t n);

#endif
