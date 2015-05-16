#ifndef FIB_H
#define FIB_H

#include <stdint.h>
#include <rte_ether.h>

struct fib_entry {
  union {
    struct {
      uint32_t next_hop;
      uint8_t  prefix_len;
    } data;
    struct {
      uint64_t mac_addr:48;
      uint64_t vlan_id:16;
      struct l3_interface *intf;
      struct arp_table_entry *arp_entry;
    } cache;
  } e;
};

#endif
