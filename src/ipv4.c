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
#include "arp.h"
#include "ipv4.h"
#include "icmp.h"
#include "global_mario.h"

#define RTE_LOGTYPE_IPV4 RTE_LOGTYPE_USER1

RTE_DEFINE_PER_LCORE(struct mbuf_queue*, routing_queue);

static int
ip_routing(struct mbuf_queue* rqueue)
{
  RTE_LOG(DEBUG, IPV4, "[%u] %s [%u] %s\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
  struct rte_mbuf **queue = rqueue->queue;
  uint16_t len = rqueue->len;
  for (uint16_t i = 0; i < len; i++) {
    struct rte_mbuf *buf = queue[i];
    struct ipv4_hdr *iphdr;
    iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);

    /* dst is our subnet */
    uint8_t next_index;
    uint32_t dst = ntohl(iphdr->dst_addr);
    int res = rte_lpm_lookup(rib, dst, &next_index);
    if(res != 0) {
      RTE_LOG(DEBUG, IPV4, "not matched lpm lookup\n");
      rte_pktmbuf_free(buf);
      continue;
    }
    
    uint32_t next_hop = next_hop_tb[next_index];
    int dst_port = is_own_subnet(intfs, next_hop);
    if(dst_port < 0) {
      rte_pktmbuf_free(buf);
      continue;
    }

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
    if(!rewrite_mac_addr(buf, dst_port)) 
      eth_enqueue_tx_packet(buf, dst_port);
  }
  rqueue->len = 0;
  return 0;
}

int
ip_enqueue_routing_pkt(struct mbuf_queue* rqueue, struct rte_mbuf* buf)
{
  RTE_LOG(DEBUG, IPV4, "[%u] %s [%u] %s\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
  rqueue->queue[(rqueue->len)++] = buf;  
  return rqueue->len == rqueue->max ? 1 : 0;
}

void
ip_enqueue_pkt(struct mbuf_queue* rqueue, struct rte_mbuf* buf)
{
  RTE_LOG(DEBUG, IPV4, "[%u] %s [%u] %s\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);

  int dst_port = is_own_subnet(intfs, ntohl(iphdr->dst_addr));
  if(dst_port < 0) {
    RTE_LOG(DEBUG, IPV4, "not own subnet\n");
    int res = ip_enqueue_routing_pkt(rqueue, buf);
    if(res) ip_routing(rqueue);
    return;
  }

  iphdr->hdr_checksum = 0;
  iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

  if(!rewrite_mac_addr(buf, dst_port))
    eth_enqueue_tx_packet(buf, dst_port);
}


void
ip_rcv(struct rte_mbuf **bufs, uint16_t n_rx)
{
  struct mbuf_queue *rq = get_routing_Q();
  for (uint16_t i = 0; i < n_rx; i++) {
    struct ipv4_hdr *iphdr;
    uint32_t ndst;
    struct rte_mbuf *buf = bufs[i];
    iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char *) + buf->l2_len);
    buf->l3_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) << 2;    
    
    /* packets to this host. */
    {
      uint32_t d = ntohl(iphdr->dst_addr);
      uint32_t s = ntohl(iphdr->src_addr);
      RTE_LOG(DEBUG, IPV4, "[%u] %s [%u] %s %u.%u.%u.%u -> %u.%u.%u.%u\n", rte_lcore_id(), __FILE__, __LINE__, __func__,
              (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff,
              (d >> 24)&0xff,(d>> 16)&0xff,(d >> 8)&0xff,d&0xff);
    }
    
    /* ignore braodcast */
    ndst = ntohl(iphdr->dst_addr);
    if (IPV4_BROADCAST <= ndst) {
      RTE_LOG(DEBUG, IPV4, "ignore broadcast.");
      rte_pktmbuf_free(buf);
      continue;
    }
    
    /* checksum check */
    uint16_t res = ~rte_ipv4_cksum(iphdr);
    if (res) {
      rte_pktmbuf_free(buf);
      continue;
    }

    int port_id = is_own_ip_addr(intfs, ndst);
    if(port_id >= 0) {      
      switch(iphdr->next_proto_id) {
        case IPPROTO_ICMP: {
          icmp_rcv(buf);
          continue;
        }
        case IPPROTO_TCP: 
        case IPPROTO_UDP: 
          RTE_LOG(DEBUG, IPV4, "[%u] %s %u %s to this router so drop\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
          ;
      }
      rte_pktmbuf_free(buf);
      continue;
    }

    /* packets to other hosts. */
    /* check the TTL */ 
    uint16_t ttl = ntohs(iphdr->time_to_live);
    if((--ttl <= 0)) {
      icmp_send_time_exceeded(buf, ndst);
      continue;
    }
    iphdr->time_to_live = htons(ttl);

    /* this includes other ports subnet */
    int dst_port = is_own_subnet(intfs, ndst);
    if(dst_port >= 0) {
      RTE_LOG(DEBUG, IPV4, "[%u] %s %u %s forwarding\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
      iphdr->hdr_checksum = 0;
      iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
      if(!rewrite_mac_addr(buf, dst_port)) 
        eth_enqueue_tx_packet(buf, dst_port);
      continue;
    }

    if (unlikely(ip_enqueue_routing_pkt(rq, buf))) {
      RTE_LOG(DEBUG, IPV4, "[%u] %s %u %s ip routing\n", rte_lcore_id(), __FILE__, __LINE__, __func__);
      ip_routing(rq);
    }
  }  
  
  ip_routing(rq);
  return ;
}
