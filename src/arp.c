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
#include "global_mario.h"
#include "arp.h"

#define mmalloc(x) rte_malloc("fdb", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_ARP_TABLE RTE_LOGTYPE_USER1

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

static void
arp_request_process(struct rte_mbuf* buf, struct arp_hdr* arphdr)
                    
{
  int res;
  struct ether_hdr*eth;
  struct arp_ipv4 *body = &arphdr->arp_data;
  if (!is_own_ip_addr(intfs , body->arp_tip)) return;
  
  res = add_arp_table_entry(arp_tb, &body->arp_sip, &body->arp_sha);
  if (res) {
    RTE_LOG(ERR, ARP_TABLE, 
            "No more space for arp table: Drop ARP request.\n");
    rte_pktmbuf_free(buf);
    return ;
  }

  struct ether_addr tmp = body->arp_tha;
  body->arp_tha = body->arp_sha;
  body->arp_sha = tmp;
  body->arp_tip = body->arp_sip;
  body->arp_sip = body->arp_tip;
  arphdr->arp_op = ARP_OP_REPLY;
  
	eth = rte_pktmbuf_mtod(buf, struct ether_hdr *);
  eth->d_addr = body->arp_tha;
  eth->s_addr = body->arp_sha;  

  eth_enqueue_tx_pkt(buf);
}

static void
arp_reply_process(struct rte_mbuf* buf, struct arp_hdr* arphdr)
                  
{
  int res = 0;
  struct ether_addr etheraddr;
  struct arp_ipv4 *body = &arphdr->arp_data;
  rte_eth_macaddr_get(buf->port, &etheraddr);
  
  if (!is_same_ether_addr(&body->arp_tha, &etheraddr)) return;
    
  res = add_arp_table_entry(arp_tb, &body->arp_sip, &body->arp_sha);
  
  rte_pktmbuf_free(buf);
}

void
arp_rcv(struct rte_mbuf* buf)
{
  struct arp_hdr* arphdr;
  arphdr = (struct arp_hdr *) (rte_pktmbuf_mtod(buf, char*) + buf->l2_len);
  if (arphdr->arp_hrd != ARP_HRD_ETHER) return ;
  // XXX some other checks

  switch(arphdr->arp_op) {
    case ARP_OP_REQUEST: {
      arp_request_process(buf, arphdr);
      break;
    }
    case ARP_OP_REPLY: {
      arp_reply_process(buf, arphdr);      
      break;
    }
  }  
}
