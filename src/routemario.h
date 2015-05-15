#ifndef ROUTEMARIO_H
#define ROUTEMARIO_H

#include <stdint.h>
#include <rte_ether.h>

struct l3_interface {
  uint16_t vlan_id;
  struct ether_addr mac;
  uint32_t ip_addr;
  uint8_t port_id;
};

struct arp_table_entry;
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

extern struct l3_interfaces l3_intfs[MAX_INTERFACES];
extern struct fib_table fib;

#endif
