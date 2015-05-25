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

#include "util.h"
#include "interfaces.h"
#include "arp.h"
#include "global_mario.h"

#define mmalloc(x) rte_malloc("fdb", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_ARP_TABLE RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_ARP RTE_LOGTYPE_USER2

struct arp_table *arp_tb;

struct arp_table*
create_arp_table(uint32_t _size)
{
  rte_srand((unsigned) time (NULL));
  uint32_t seed = (uint32_t) rte_rand();
  uint32_t size = (uint32_t) POWERROUND(_size);
  size = size > RTE_HASH_ENTRIES_MAX? RTE_HASH_ENTRIES_MAX : size;

  struct arp_table *table;
  table = (struct arp_table*) mmalloc(sizeof(struct arp_table) +
                                      sizeof(struct arp_table_entry) * size);
  if (table == NULL) {
    RTE_LOG( ERR, ARP_TABLE, "cannot allocate memory for table.\n");
    goto out;
  }
  
  struct rte_hash_parameters params = {
    .name = "arp_table",
    .entries = size,
    .bucket_entries = RTE_HASH_BUCKET_ENTRIES_MAX,
    .key_len = 4,
    .hash_func = rte_jhash,
    .hash_func_init_val = seed,
    .socket_id = (int) rte_socket_id()
  };
  table->handler = rte_hash_create(&params);
  if (table->handler == NULL) {
    RTE_LOG(ERR, ARP_TABLE,
            "cannot create rte_hash: %s.\n", rte_strerror(rte_errno));
    goto free;
  }

  return table;
free:
  mfree(table->handler);
out:
  return NULL;  
}

void
destroy_arp_table(struct arp_table* table)
{
  rte_hash_free(table->handler);
  mfree(table->items);
}

int
add_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr,
                    const struct ether_addr* addr)
{
  int32_t key = rte_hash_add_key(table->handler, ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    ether_addr_copy(addr, &entry->eth_addr);
    entry->ip_addr = *ip_addr;
    entry->expire = ARP_TABLE_EXPIRE_TIME;
    return 0;
  }

  if (key == -ENOSPC) {
    RTE_LOG(WARNING, ARP_TABLE, "no space in the hash for this key.\n");
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOSPC:
      RTE_LOG(WARNING, ARP_TABLE, "no space in the hash for this key.\n");
      /* break through */
  }
  return key;
}

int
remove_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr)
{
  int32_t key = rte_hash_del_key(table->handler, ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    ether_addr_copy((struct ether_addr*) "000000", &entry->eth_addr);
    entry->ip_addr = 0;
    entry->expire = 0;
    return 0;
  }

  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOENT:
      RTE_LOG(WARNING, ARP_TABLE, "the key is not found.\n");
      /* break through */
  }
  return key;
}

struct arp_table_entry*
lookup_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr)
{
  int32_t key = rte_hash_lookup(table->handler, (void*) ip_addr);
  if (key >= 0) {
    struct arp_table_entry *entry = &table->items[key];
    return entry;
  }
  switch (-key) {
    case EINVAL:
      RTE_LOG(WARNING, ARP_TABLE, "Invalid parameters.\n");
      break;
    case ENOENT:
      ;
      //RTE_LOG(WARNING, ARP_TABLE, "the key is not found.\n");
      /* break through */
  }
  return NULL;
}

int
lookup_bulk_arp_table_entries(struct arp_table *table,
                              const uint32_t **ip_addrs,
                              uint32_t num_entry,
                              struct arp_table_entry** entries)
{
  int32_t positions[num_entry];
  int res = rte_hash_lookup_bulk(table->handler, (const void**) ip_addrs,
                                 num_entry, (int32_t*) positions);
  if (res ==  0) {
    for (uint32_t i = 0; i < num_entry; i++) {
      // XXX: inline extraction 
      entries[i] = &table->items[positions[i]];
    }
    return 0;
  }
  
  RTE_LOG(ERR, ARP_TABLE, "error.\n");
  return res;
}

void
arp_send_request(struct rte_mbuf* buf, uint32_t tip, uint8_t port_id)
{
  if (buf == NULL) {
    buf = rte_pktmbuf_alloc(rmario_pktmbuf_pool);
  }
  struct arp_hdr* arphdr;
  struct ether_hdr* eth = rte_pktmbuf_mtod(buf, struct ether_hdr*);
  arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  arphdr->arp_hrd = htons(ARP_HRD_ETHER);
  arphdr->arp_pro = htons(ETHER_TYPE_IPv4);
  arphdr->arp_hln = ETHER_ADDR_LEN;
  arphdr->arp_pln = sizeof(uint32_t);
  arphdr->arp_op  = htons(ARP_OP_REQUEST);

  struct l3_interface* l3_if = get_l3_interface_port_id(intfs, port_id);
  if (l3_if == NULL) goto free;
  struct arp_ipv4 *body = &arphdr->arp_data;
  body->arp_tip = tip;
  body->arp_sip = htonl(l3_if->ip_addr);
  memset(&body->arp_tha, 0xff, ETHER_ADDR_LEN);
  memset(&eth->d_addr  , 0xff, ETHER_ADDR_LEN);
  ether_addr_copy(&l3_if->mac, &body->arp_sha);
  ether_addr_copy(&l3_if->mac, &eth->s_addr);
  eth->ether_type = htons(ETHER_TYPE_ARP);
  //buf->pkt_len = 46;  
  __eth_enqueue_tx_pkt(buf, port_id);
  return;
free:
  rte_pktmbuf_free(buf);
}

static void
arp_request_process(struct rte_mbuf* buf, struct arp_hdr* arphdr)
{
  struct ether_hdr*eth;
  struct arp_ipv4 *body = &arphdr->arp_data;
  int port_id = is_own_ip_addr(intfs , ntohl(body->arp_tip));
  if (port_id < 0) goto out;
  
  struct ether_addr* port_mac = get_macaddr_with_port(intfs, port_id);;
  if (port_mac == NULL) {
    RTE_LOG(ERR, ARP,  "No macaddr registered.\n");
    goto out;
  }

  int res = add_arp_table_entry(arp_tb, &body->arp_sip, &body->arp_sha);
  if (res) {
    RTE_LOG(ERR, ARP, "No more space for arp table: Drop ARP request.\n");
    goto out;
  }

  uint32_t tmp_ip = body->arp_tip;
  body->arp_tip = body->arp_sip;
  body->arp_sip = tmp_ip;
  ether_addr_copy(&body->arp_sha, &body->arp_tha);
  ether_addr_copy(port_mac     , &body->arp_sha);
  arphdr->arp_op = htons(ARP_OP_REPLY);
  
  eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  ether_addr_copy(&body->arp_tha, &eth->d_addr);
  ether_addr_copy(&body->arp_sha, &eth->s_addr);
  //buf->pkt_len = 46;
  /*
  {
    struct arp_ipv4 *body = &arphdr->arp_data;
    uint8_t *a = (body->arp_sha).addr_bytes;
    RTE_LOG(DEBUG, ARP, 
            "ARP src %02x:%02x:%02x:%02x:%02x:%02x\n",
            a[0], a[1], a[2], a[3], a[4], a[5]);

    a = (body->arp_tha).addr_bytes;
    RTE_LOG(DEBUG, ARP, 
            "ARP target %02x:%02x:%02x:%02x:%02x:%02x\n",
            a[0], a[1], a[2], a[3], a[4], a[5]);

    a = (eth->s_addr).addr_bytes;
    RTE_LOG(DEBUG, ARP, 
            "MAC src %02x:%02x:%02x:%02x:%02x:%02x\n",
            a[0], a[1], a[2], a[3], a[4], a[5]);

    a = (eth->d_addr).addr_bytes;
    RTE_LOG(DEBUG, ARP, 
            "MAC dst %02x:%02x:%02x:%02x:%02x:%02x\n",
            a[0], a[1], a[2], a[3], a[4], a[5]);
    
  }
  // */
  __eth_enqueue_tx_pkt(buf, buf->port);
  return ;
out:
  rte_pktmbuf_free(buf);
}

static void
arp_reply_process(struct rte_mbuf* buf, struct arp_hdr* arphdr, bool internal)
                  
{
  int res = 0;
  struct arp_ipv4 *body = &arphdr->arp_data;

  res = add_arp_table_entry(arp_tb, &body->arp_sip, &body->arp_sha);  
  if (res) 
    RTE_LOG(WARNING, ARP, "fail to add arp entry\n");
  
  if (internal) return ;

  // broadcast to all the other nodes
  uint8_t port_num = rte_eth_dev_count();
  for (uint8_t port_id = 0, i = 0; port_id < port_num; port_id++) {
    if (port_id == buf->port) continue;
    
    struct rte_mbuf* _buf = buf;
    if(++i != (port_num - 1))
       _buf = rte_pktmbuf_clone(buf, rmario_pktmbuf_pool);
    
    __eth_enqueue_tx_pkt(buf, port_id);
  }
}

void
arp_rcv(struct rte_mbuf* buf)
{
  struct arp_hdr* arphdr;
  arphdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  if (ntohs(arphdr->arp_hrd) != ARP_HRD_ETHER ||
      ntohs(arphdr->arp_pro) != ETHER_TYPE_IPv4 ||
      arphdr->arp_hln        != ETHER_ADDR_LEN ||
      arphdr->arp_pln        != sizeof(uint32_t) ) return ;

  switch(ntohs(arphdr->arp_op)) {
    case ARP_OP_REQUEST: {
      arp_request_process(buf, arphdr);
      return ;
    }
    case ARP_OP_REPLY: {
      arp_reply_process(buf, arphdr, false);
      return ;
    }
  }
  rte_pktmbuf_free(buf);
}

static void
arp_internal_request_process(struct rte_mbuf* buf, struct arp_hdr* arphdr)
{
  uint8_t dst_port = get_nic_queue_id();
  if(get_nic_queue_id() == _mid) {
    struct ether_addr mac;
    rte_eth_macaddr_get(dst_port, &mac);

    struct ether_hdr *eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    struct arp_ipv4 *body = &arphdr->arp_data;
    ether_addr_copy(&mac, &body->arp_sha);
    memset(&eth->d_addr  , 0xff, ETHER_ADDR_LEN);
    ether_addr_copy(&mac, &eth->s_addr);
  }
  __eth_enqueue_tx_pkt(buf, dst_port); 
}

void
arp_internal_rcv(struct rte_mbuf* buf)
{
  struct arp_hdr* arphdr;
  arphdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  if (ntohs(arphdr->arp_hrd) != ARP_HRD_ETHER ||
      ntohs(arphdr->arp_pro) != ETHER_TYPE_IPv4 ||
      arphdr->arp_hln        != ETHER_ADDR_LEN ||
      arphdr->arp_pln        != sizeof(uint32_t) ) return ;
    
      
  switch(ntohs(arphdr->arp_op)) {
    case ARP_OP_REQUEST: {
      arp_internal_request_process(buf, arphdr);
      return ;
    }
    case ARP_OP_REPLY: {
      arp_reply_process(buf, arphdr, true);      
      return ;
    }
  }
  rte_pktmbuf_free(buf);
}
