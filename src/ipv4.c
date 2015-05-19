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
#include <arpa/inet.h>

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
#include <rte_ip.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_lpm.h>
#include <rte_per_lcore.h>

#include "util.h"
#include "interfaces.h"
#include "mbuf_queue.h"
#include "ipv4.h"
#include "icmp.h"
#include "global_mario.h"

#define RTE_LOGTYPE_IPV4 RTE_LOGTYPE_USER1

RTE_DEFINE_PER_LCORE(struct mbuf_queue*, routing_queue);

static uint16_t
calc_checksum(uint16_t *buf, uint32_t len)
{
  uint32_t sum = 0;

  while (len > 1) {
    sum += *buf;
    buf++;
    len -= 2;
  }
  if (len == 1) 
    sum += *(uint8_t*) buf;

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (uint16_t) ~sum;
}

static int
ip_routing(struct mbuf_queue* rqueue)
{
  struct rte_mbuf **queue = rqueue->queue;
  uint16_t len = rqueue->len;
  for (uint16_t i = 0; i < len; i++) {
    struct rte_mbuf *buf = queue[i];
    struct ipv4_hdr *iphdr;
    iphdr = (struct ipv4_hdr*) rte_pktmbuf_mtod(buf, char*) + buf->l2_len;
                                 
    uint32_t dst = iphdr->dst_addr;
    /* dst is our subnet */

    uint8_t next_index;
    if(rte_lpm_lookup(rib, dst, &next_index) != 0) {
      RTE_LOG(INFO, IPV4, "not matched lpm lookup\n");
      rte_pktmbuf_free(buf);
      continue;
    }
    
    uint32_t next_hop = next_hop_tb[next_index];
    uint8_t dst_port = is_own_subnet(intfs, next_hop);
    if(dst_port < 0) {
      rte_pktmbuf_free(buf);
      continue;
    }
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
    eth_enqueue_tx_pkt(buf, dst_port);    
  }
  rqueue->len = 0;
  return 0;
}

int
ip_enqueue_routing_pkt(struct mbuf_queue* rqueue, struct rte_mbuf* buf)
{
  struct mbuf_queue *r_queue = get_routing_Q();
  r_queue->queue[(r_queue->len)++] = buf;  
  return r_queue->len == r_queue->max ? 1 : 0;
}

void
ip_enqueue_pkt(struct mbuf_queue* rqueue, struct rte_mbuf* buf)
{
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  {
    uint32_t d = ntohl(iphdr->dst_addr);
    uint32_t s = ntohl(iphdr->src_addr);
    RTE_LOG(INFO, IPV4, "%s: %u.%u.%u.%u -> %u.%u.%u.%u\n", __func__,
            (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff,
            (d >> 24)&0xff,(d>> 16)&0xff,(d >> 8)&0xff,d&0xff);
  }


  int dst_port = is_own_subnet(intfs, ntohl(iphdr->dst_addr));
  if(dst_port < 0) {
    int res = ip_enqueue_routing_pkt(rqueue, buf);
    if(res) ip_routing(rqueue);
    return;
  }

  RTE_LOG(INFO, IPV4, "dest is in the same LAN\n", dst_port);
  iphdr->hdr_checksum = 0;
  iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
  eth_enqueue_tx_pkt(buf, dst_port);
}


void
ip_rcv(struct rte_mbuf **bufs, uint16_t n_rx)
{
  RTE_LOG(INFO, IPV4, "%s %upacket(s)\n", __func__, n_rx);
  struct mbuf_queue *rq = get_routing_Q();
  for (uint16_t i = 0; i < n_rx; i++) {
    int res = 0;
    struct ipv4_hdr *iphdr;
    uint32_t ndst;
    struct rte_mbuf *buf = bufs[i];
    iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    buf->l3_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) << 2;    
    
    /* packets to this host. */
    {
      uint32_t d = ntohl(iphdr->dst_addr);
      uint32_t s = ntohl(iphdr->src_addr);
      RTE_LOG(INFO, IPV4, "%u.%u.%u.%u -> %u.%u.%u.%u\n",
              (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff,
              (d >> 24)&0xff,(d>> 16)&0xff,(d >> 8)&0xff,d&0xff);
    }

    ndst = ntohl(iphdr->dst_addr);
    int port_id = is_own_ip_addr(intfs, ndst);
    if(port_id >= 0) {      
      {
        uint32_t s = ntohl(intfs->list[port_id].ip_addr);
        RTE_LOG(INFO, IPV4, "Port-%d: %u.%u.%u.%u\n", port_id,
                (s >>24)&0xff,(s >>16)&0xff,(s >>8)&0xff,s&0xff);
      }
      switch(iphdr->next_proto_id) {
        case IPPROTO_ICMP: {
          icmp_rcv(buf);
          continue;
        }
        case IPPROTO_TCP: 
        case IPPROTO_UDP: 
          ;
      }
      rte_pktmbuf_free(buf);
      continue;
    }

    /* packets to other hosts. */
    /* check the TTL */    
    if((--(iphdr->time_to_live) <= 0)) {
      icmp_send_time_exceeded(buf, ndst);
      continue;
    }

    /* this includes other ports subnet */
    int dst_port = is_own_subnet(intfs, ndst);
    if(dst_port >= 0) {
      RTE_LOG(INFO, IPV4, "Port-%d: forwarding\n", dst_port);
      iphdr->hdr_checksum = 0;
      iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
      eth_enqueue_tx_pkt(buf, dst_port);
      continue;
    }

    res = ip_enqueue_routing_pkt(rq, buf);
    if (unlikely(res)) {
      ip_routing(rq);
    }
  }  
  
  ip_routing(rq);
  return ;
}
