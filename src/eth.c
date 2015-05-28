/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>

#include "eth.h"
#include "mbuf_queue.h"
#include "fdb.h"
#include "ipv4.h"
#include "vlb.h"
#include "global_mario.h"

#define RTE_LOGTYPE_ETH RTE_LOGTYPE_USER1

RTE_DEFINE_PER_LCORE(struct mbuf_queues *, eth_tx_queue);
RTE_DEFINE_PER_LCORE(uint16_t, nic_queue_id);

int
rewrite_mac_addr(struct rte_mbuf *buf, uint8_t dst_port, uint32_t next_hop)
{
  if(dst_port < 0) 
    rte_pktmbuf_free(buf);

  struct ether_addr mac;
  rte_eth_macaddr_get(dst_port, &mac);
#ifndef NDEBUG
  {
    uint32_t s = ntohl(next_hop);
    RTE_LOG(DEBUG, ETH, "[%u] %s [%u] %s %u.%u.%u.%u\n", rte_lcore_id(), __FILE__, __LINE__, __func__,
            (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff);
  }
#endif  

  struct ipv4_hdr *iphdr;
  struct arp_table_entry *entry;
  struct ether_hdr *eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  entry = lookup_arp_table_entry(arp_tb, &next_hop);
  if ((entry == NULL) || (is_expired(entry))) {
    // XXX right ?
    arp_send_request(buf, next_hop, dst_port);
    return 1;
  }
  ether_addr_copy(&entry->eth_addr, &eth->d_addr);
  ether_addr_copy(&mac, &eth->s_addr);
  return 0;
}

void
eth_queue_xmit(uint8_t dst_port, uint16_t n)
{
  uint16_t ret;  
  struct rte_mbuf **queue = (get_eth_tx_Q(dst_port))->queue;
  ret = rte_eth_tx_burst(dst_port, get_nic_queue_id(), queue, n);
  if (unlikely(ret < n)) {
#ifndef NDEBUG
    RTE_LOG(WARNING, ETH, "fail to %d packets xmit.\n", (n - ret));
#endif  
    do {
      rte_pktmbuf_free(queue[ret]);
    } while(++ret < n);
  }

  get_eth_tx_Q(dst_port)->len = 0;
  return ;
}

void
__eth_enqueue_tx_pkt(struct rte_mbuf *buf, uint8_t dst_port)
{
  struct mbuf_queue* tx_queue = get_eth_tx_Q(dst_port);  
  uint16_t len = tx_queue->len;
  tx_queue->queue[len++] = buf;
  
  if (unlikely(len == tx_queue->max)) {
    eth_queue_xmit(dst_port, len);
    len = 0;
  }

  tx_queue->len = len;
  return ;
}

/* this function is called only when routing packets from external ports. */
void
eth_random_enqueue_tx_pkt(struct rte_mbuf *buf, uint8_t dst_port)
{
  struct ether_hdr *eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  if (dst_port == _mid) {
    RTE_LOG(CRIT, ETH,
            "Don't call this function to the packet to the external port\n");
    assert(false);
  }

#ifdef VLB
  uint8_t middle_node = forwarding_node_id(buf->hash.rss);
#else
  uint8_t middle_node = dst_port;
#endif
  ether_addr_copy(&eth->d_addr, &eth->s_addr);
  eth->d_addr.addr_bytes[0] = (uint8_t)(0xf + (dst_port << 4));
#ifndef NDEBUG
  {
    uint8_t* a = (eth->d_addr).addr_bytes;
    RTE_LOG(DEBUG, ETH, "[%u] %s [%u] %s %02x:%02x:%02x:%02x:%02x:%02x dst_port %u middle: %u\n",
            rte_lcore_id(), __FILE__, __LINE__, __func__, 
            a[0], a[1], a[2], a[3], a[4], a[5], dst_port, middle_node);
  }
#endif  
  __eth_enqueue_tx_pkt(buf, middle_node);
}

void
eth_enqueue_tx_packet(struct rte_mbuf *buf, uint8_t dst_port)
{
  if (dst_port == _mid)
    __eth_enqueue_tx_pkt(buf, dst_port);
  else
    eth_random_enqueue_tx_pkt(buf, dst_port);
}

#ifndef L2SWITCHING
/*
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
*/

static void
ether_switching(struct rte_mbuf* buf, uint8_t src_port)
{
  struct fdb_table *fdb = fdb_tb;
  struct fdb_entry *dst_entry;
  struct ether_hdr *eth;
  uint8_t dst_port;

	eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  dst_entry = lookup_fdb_entry(fdb, &eth->d_addr);
  add_fdb_entry(fdb, &eth->s_addr, src_port);;
  if (dst_entry == NULL) {
    // XXX
    ; //eth_flooding(buf, src_port);
  } else {
    // XXX
    // must check aging time. if expire an entry, flooding pkt
    dst_port = (uint8_t) dst_entry->port;
    __eth_enqueue_tx_pkt(buf, dst_port);

  }
}
#endif

void
eth_input(struct rte_mbuf** bufs, uint16_t n_rx, uint8_t src_port)
{
  struct ether_addr mac;
  rte_eth_macaddr_get(src_port, &mac);
  assert(_mid == src_port);
  for(uint32_t i = 0; i < n_rx; i++) {
#ifndef NDEBUG
    RTE_LOG(DEBUG, ETH, "[%u] %s [%u] %s %u\n", rte_lcore_id(), __FILE__, __LINE__, __func__, i);
#endif
    struct rte_mbuf* buf = bufs[i];
    rte_prefetch0(rte_pktmbuf_mtod(buf, void *));
    
    struct ether_hdr *eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    buf->l2_len = ETHER_HDR_LEN;    
    if((!is_same_ether_addr(&eth->d_addr, &mac)) &&
       (!is_broadcast_ether_addr(&eth->d_addr))) {
      rte_pktmbuf_free(buf);
      continue;
    }
    switch (ntohs(eth->ether_type)) {
      case ETHER_TYPE_ARP: {
        arp_rcv(buf);
        continue;
      }
      case ETHER_TYPE_IPv4: {
        ip_rcv(&buf, 1);
        continue;
      }
      case ETHER_TYPE_IPv6: {
        ;
      }
    }
    rte_pktmbuf_free(buf);
  }
}

void
eth_internal_input(struct rte_mbuf** bufs, uint16_t n_rx, uint8_t src_port)
{
#ifndef NDEBUG
  RTE_LOG(DEBUG, ETH, "[Core-%u][Q#%u][Port-%u] %s\n",
          rte_lcore_id(), get_nic_queue_id(), src_port,  __func__);
#endif

  uint8_t dst_port = get_nic_queue_id();
  struct ether_addr mac;
  rte_eth_macaddr_get(dst_port, &mac);
  for(uint32_t i = 0; i < n_rx; i++) {
    struct rte_mbuf* buf = bufs[i];
    rte_prefetch0(rte_pktmbuf_mtod(buf, void *));

    struct ether_hdr *eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    buf->l2_len = ETHER_HDR_LEN;
#ifndef NDEBUG
    {
      uint8_t* a = (eth->s_addr).addr_bytes;
      RTE_LOG(DEBUG, ETH, 
              "%s MAC src %02x:%02x:%02x:%02x:%02x:%02x\n",
              __func__, a[0], a[1], a[2], a[3], a[4], a[5]);
      
      a = (eth->d_addr).addr_bytes;
      RTE_LOG(DEBUG, ETH, 
              "%s MAC dst %02x:%02x:%02x:%02x:%02x:%02x\n",
              __func__, a[0], a[1], a[2], a[3], a[4], a[5]);
  
    }
#endif
    switch (ntohs(eth->ether_type)) {
      case ETHER_TYPE_ARP: {
        arp_internal_rcv(buf);
        continue;
      }
      case ETHER_TYPE_IPv4: {
#ifndef NDEBUG
        {
          struct ipv4_hdr *iphdr;
          iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
          uint32_t d = ntohl(iphdr->dst_addr);
          uint32_t s = ntohl(iphdr->src_addr);
          RTE_LOG(DEBUG, ETH, "[%u -> %u] %u.%u.%u.%u -> %u.%u.%u.%u\n",
                  buf->port, dst_port,
                  (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff,
                  (d >> 24)&0xff,(d>> 16)&0xff,(d >> 8)&0xff,d&0xff);
        }
#endif
        if (dst_port == _mid) { // internal -> external port
#ifndef NDEBUG
          RTE_LOG(DEBUG, ETH, "to external port\n");
#endif
          ether_addr_copy(&eth->s_addr, &eth->d_addr);
          ether_addr_copy(&mac, &eth->s_addr);
        } else {  // internal -> internal
          ;
#ifndef NDEBUG
          RTE_LOG(DEBUG, ETH, "to node #%u\n", dst_port);
#endif  
        }
        __eth_enqueue_tx_pkt(buf, dst_port);
        continue;
      }
    }
    rte_pktmbuf_free(buf);
  }
}
