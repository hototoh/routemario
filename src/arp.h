#ifndef ARP_H
#define ARP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#define ARP_TABLE_EXPIRE_TIME 300

struct arp_table_entry {
  struct ether_addr eth_addr;
  uint16_t vlan_id;
  uint32_t ip_addr;
  uint32_t expire;
};

struct arp_table {
  struct rte_hash *handler;
  struct arp_table_entry items[0];
};

// TODO imple
static inline bool
is_expired(struct arp_table_entry* e)
{
  return false;
}

struct arp_table*
create_arp_table(uint32_t size);

void
destroy_arp_table(struct arp_table* table);

int
add_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr,
                    const struct ether_addr* addr);

int
remove_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr);

struct arp_table_entry*
lookup_arp_table_entry(struct arp_table* table, const uint32_t *ip_addr);

int
lookup_bulk_arp_table_entries(struct arp_table *talbe, 
                              const uint32_t **ip_addrs,
                              uint32_t num_entry,
                              struct arp_table_entry** entries);

void
arp_send_request(struct rte_mbuf* buf, uint32_t dst, uint8_t port_id);

void
arp_rcv(struct rte_mbuf* buf);

void
arp_internal_rcv(struct rte_mbuf* buf);
#endif
