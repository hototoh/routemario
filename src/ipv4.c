/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_per_lcore.h>

#include "util.h"
#include "ipv4.h"
#include "interfaces.h"
#include "routemario.h"

RTE_DEFINE_PER_LCORE(struct mbuf_queue, routing_queue);

static int
ip_routing(struct mbuf_queue* routing_queue)
{
  
  return 0;
}

int
ip_enqueue_routing_pkt(struct mbuf_queue* routing_queue, struct mbuf* buf)
{
  
}

void
ip_rcv(struct rte_mbuf **bufs, uint16_t n_rx)
{
  for (uint16_t i = 0; i < n_rx; i++) {
    int res = 0;
    struct rte_mbuf *buf = bufs[i];
    struct ipv4_hdr *iphdr;
    struct l3_interfaces *intfs;
    iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    buf->l3_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) << 2;
    
    /* packets to this host. */
    if(is_own_ip_addr(intfs, iphdr->dst_addr)) {
      switch(iphdr->next_proto_id) {
        case IPPROTO_ICMP: {
          icmp_recv(buf);
          break;
        }
        case IPPROTO_TCP: {
          rte_pktmbuf_free(buf);
          break;
        }
        case IPPROTO_UDP: {
          rte_pktmbuf_free(buf);
          break;
        }
      }
      continue;
    }

    /* packets to other hosts. */
    /* check the TTL */
    if((--(iphdr->time_to_live) <= 0)) {
      icmp_send_time_exceeded(buf);
      continue;
    }

    res = ip_enqueue_routing_pkt(get_mbuf_queue(), buf);
    if (unlikely(res)) {
      ip_routing(get_mbuf_queue());
    }
  }

  ip_routing(get_mbuf_queue());
  return 0;
}
