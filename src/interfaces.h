#ifndef INTERFACES_H
#define INTERFACES_H

#include <rte_ether.h>
#include <rte_malloc.h>

struct l3_interface {
  uint16_t vlan_id;
  struct ether_addr mac;
  uint32_t ip_addr;
  uint32_t ip_mask;
  uint8_t port_id;
};

#define MAX_PORT_SIZE 8
struct l3_interfaces {
  uint16_t len;
  uint16_t max;
  struct l3_interface list[0];
};

struct l3_interfaces*
create_l3_interfaces(uint16_t len);

void
destroy_l3_interfaces(struct l3_interfaces *l3ifs);

struct l3_interface*
get_l3_interface_port_id(struct l3_interfaces *l3ifs, uint8_t port_id);

void
set_l3_interface(struct l3_interface *l3if, const uint16_t vlan_id,
                 const struct ether_addr *addr, const uint32_t ip_addr,
                 const uint32_t ip_mask,  const uint8_t port_id);
                    
int
is_own_ip_addr(struct l3_interfaces *l3ifs, uint32_t addr);

int
is_own_subnet(struct l3_interfaces *l3ifs, uint32_t addr);

struct ether_addr*
get_macaddr_with_port(struct l3_interfaces * l3ifs, uint8_t port_id);
#endif
