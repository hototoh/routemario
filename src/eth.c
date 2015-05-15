/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rte_per_lcore.h>
#include "arp.h"

RTE_DEFINE_PER_LCORE(struct mbuf_queue, eth_tx_queue[MAX_PORT]);
RTE_DEFINE_PER_LCORE(uint16_t, nic_queue_id);

void
eth_queue_xmit(uint8_t dst_port, unsigned n)
{
  struct rte_mbuf **m_table = (get_eth_tx_queue())[dst_port]->m_table;
  unsigned ret;
  unsigned queue_id;
  
  ret = rte_eth_tx_burst(dst_port, nic_queue_id, m_table, n);
  //port_statistics[dst_port].tx += ret;
  if (unlikely(ret < n)) {
    //port_statistics[dst_port].dropped += (n - ret);
    do {
      rte_pktmbuf_free(m_table[ret]);
    } while(++ret < n);
  }
  return ;
}

static void
__eth_enqueue_tx_pkt(struct rte_mbuf *buf, uint8_t dst_port)
{
  struct mbuf_queue* tx_queue = (get_eth_tx_queue())[dst_port];
  unsigned len = tx_queue->len;
  tx_queue[dst_port].m_table[len++] = buf;
  
  if (unlikely(len == MAX_PKT_BURST)) {
    eth_queue_xmit(dst_port, len);
    len = 0;
  }

  env->tx_mbufs[dst_port].len = len;
  return ;
}

void
eth_enqueue_tx_pkt(struct rte_mbuf *buf)
{
  // lookup fib table and set mac address & decide the dst-port;
  uint8_t dst_port;
  __eth_enqueue_tx_pkt(buf, dst_port);
}

static void
eth_flooding(struct rte_mbuf *buf, uint8_t src_port)
{
  uint8_t n = env->n_port;
  uint8_t i = 0;
  
  for (uint8_t port_id = 0; port_id < n; port_id++) {
    struct rte_mbuf *buff;
    if (port_id == src_port) continue;
    if (++i != n-1)
      buff = rte_pktmbuf_clone(buf, eth_pktmbuf_pool);
    else
      buff = buf;
    eth_enqueue_tx_pkt(buff, port_id);
  }
}

static void
ether_switching(struct rte_mbuf* buf, uint8_t src_port)
{
  struct fdb_table *fdb = env->fdb;
  struct fdb_entry *dst_entry;
  struct ether_hdr *eth;
  uint8_t dst_port;

	eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  dst_entry = lookup_fdb_entry(fdb, &eth->d_addr);
  add_fdb_entry(fdb, &eth->s_addr, src_port);;
  if (dst_entry == NULL) {
    eth_flooding(buf, src_port);
  } else {
    // XXX
    // must check expire & if so, flooding
    dst_port = dst_entry->port;
    eth_enqueue_tx_pkt(buf, dst_port);
  }
}

int
eth_input(struct rte_mbuf** bufs, unsigned n_rx, uint8_t src_port)       
{
  for(uint32_t i = 0; i < n_rx; i++) {
    int res = 0;
    struct rte_mbuf* pkt = bufs[i];
    rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
    
    struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    RTE_LOG(INFO, MARIO_ETH, "%s:\n"
            "\tl2_len: %d\n"
            "\tl3_len: %d\n"
            "\tl4_len:%d\n",
            __func__, pkt->l2_len, pkt->l3_len, pkt->l4_len);

    pkt->l2_len = ETHER_HDR_LEN;
    switch (eth->ether_type) {
      case ETHER_TYPE_ARP: {
        res = arp_rcv(pkt);
        break;
      }
      case ETHER_TYPE_IPv4: {
        res = ip_rcv(pkt);
        break;
      }
      case ETHER_TYPE_IPv6: {
        ;
        break;
      }
    }
  }
}
