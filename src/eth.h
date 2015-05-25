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

#define MAX_PKT_BURST 1
#define MAX_PORT 4

void
rewrite_mac_addr(struct rte_mbuf *buf);

void
eth_input(struct rte_mbuf** bufs, uint16_t n_rx, uint8_t src_port);

void
eth_internal_input(struct rte_mbuf** bufs, uint16_t n_rx, uint8_t src_port);

void
__eth_enqueue_tx_pkt(struct rte_mbuf *buf, uint8_t dst_port);

/* this function is called from upper layer function */
void
eth_enqueue_tx_pkt(struct rte_mbuf *buf, uint8_t dst_port);

/* this function is called from main loop function */
void
eth_queue_xmit(uint8_t dst_port, uint16_t n);

#endif
