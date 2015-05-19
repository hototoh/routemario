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
#include <netinet/ip_icmp.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_icmp.h>

#include "ipv4.h"
#include "icmp.h"
#include "global_mario.h"

#define RTE_LOGTYPE_ICMP RTE_LOGTYPE_USER1
#define DEFAULT_TTL 255

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

void
icmp_send(struct rte_mbuf *buf)
{
  RTE_LOG(WARNING, ICMP, "icmp_send is NOT implemented.");
  rte_pktmbuf_free(buf);
}

void
icmp_send_time_exceeded(struct rte_mbuf *buf, uint32_t dst_ip_addr)
{
  RTE_LOG(WARNING, ICMP, "ICMP time exceeded is NOT implemented.");
  rte_pktmbuf_free(buf);
}

void
icmp_send_destination_unreachable(struct rte_mbuf *buf, uint32_t dst_ip_addr)
{
  RTE_LOG(WARNING, ICMP, "ICMP destination unreachable is NOT implemented.");
  rte_pktmbuf_free(buf);
}


static void
icmp_proc_echo(struct rte_mbuf *buf, struct icmp_hdr *icmphdr)
{
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  uint32_t data_len = (uint32_t) (ntohs(iphdr->total_length) - buf->l3_len);

  icmphdr->icmp_type = ICMP_ECHOREPLY;
  icmphdr->icmp_code = 0;
  icmphdr->icmp_cksum = 0;
  icmphdr->icmp_cksum = calc_checksum((uint16_t *)icmphdr, data_len);
  
  // swap src and dst addr
  uint32_t tmp = iphdr->src_addr;
  iphdr->src_addr = iphdr->dst_addr;
  iphdr->dst_addr = tmp;  
  iphdr->time_to_live = DEFAULT_TTL;
  iphdr->hdr_checksum = calc_checksum((uint16_t *)iphdr , buf->l3_len);

  ip_enqueue_pkt(get_routing_Q() , buf);
}

static void
icmp_proc_echo_reply(struct rte_mbuf *buf, struct icmp_hdr *icmphdr)
{
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  uint32_t s_addr = iphdr->src_addr;
  RTE_LOG(INFO, ICMP, "get icmp reply packet from %u.%u.%u.%u\n",
          (s_addr >> 24) & 0xff, (s_addr >> 16) & 0xff,
          (s_addr >> 8) & 0xff, s_addr & 0xff);
  rte_pktmbuf_free(buf);
}

static void
icmp_proc_time_exceeded(struct rte_mbuf *buf, struct icmp_hdr *icmphdr)
{
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  uint32_t s_addr = iphdr->src_addr;
  RTE_LOG(INFO, ICMP, "get icmp time exceeded packet from %u.%u.%u.%u\n",
          (s_addr >> 24) & 0xff, (s_addr >> 16) & 0xff,
          (s_addr >> 8) & 0xff, s_addr & 0xff);
  rte_pktmbuf_free(buf);
}

void
icmp_rcv(struct rte_mbuf *buf)
{
  RTE_LOG(DEBUG, ICMP, "%s\n", __func__);
  struct icmp_hdr *icmphdr;
  struct ipv4_hdr *iphdr;
  iphdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  icmphdr = (struct icmp_hdr *) ((char*) iphdr + buf->l3_len);
  uint32_t data_len = (uint32_t) (ntohs(iphdr->total_length) - buf->l3_len);
  uint16_t res = calc_checksum((uint16_t *)icmphdr, data_len);
  if (res) {
    RTE_LOG(DEBUG, ICMP, "checksum error\n");
    goto out;
  }

  switch(icmphdr->icmp_type) {
    case ICMP_ECHOREPLY:
      icmp_proc_echo_reply(buf, icmphdr);
      return ;
    case ICMP_ECHO:
      icmp_proc_echo(buf, icmphdr);
      return ;
    case ICMP_TIME_EXCEEDED:
      icmp_proc_time_exceeded(buf, icmphdr);
      return ;
  }
out:
  rte_pktmbuf_free(buf);
}
