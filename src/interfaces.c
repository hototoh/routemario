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

#include <rte_config.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_ethdev.h>

#include "interfaces.h"

#define RTE_LOGTYPE_L3IF RTE_LOGTYPE_USER1

#define mmalloc(x) rte_malloc("L3IF", (x), 0)
#define mfree(x) rte_free((x))

struct l3_interfaces *intfs;

struct l3_interfaces*
create_l3_interfaces(uint16_t len)
{
  struct l3_interfaces *l3_ifs;
  size_t size = sizeof(struct l3_interfaces) +
                sizeof(struct l3_interface)  * len;
  l3_ifs = (struct l3_interfaces*) mmalloc(size);
  if (l3_ifs == NULL) {
    RTE_LOG(ERR, L3IF, "cannot allocate mmeory\n");
    return NULL;
  }

  l3_ifs->len = 0;
  l3_ifs->max = len;
  return l3_ifs;
}

void
destroy_l3_interfaces(struct l3_interfaces *l3_ifs)
{
  mfree(l3_ifs);
}

void
set_l3_interfaces(struct l3_interface *l3if, const uint16_t vlan_id,
                  const struct ether_addr *addr, const uint32_t ip_addr,
                  const uint32_t ip_mask,  const uint8_t port_id)
{
  l3if->vlan_id = vlan_id;
  l3if->ip_addr = ip_addr;
  l3if->port_id = port_id;
  ether_addr_copy(addr, &l3if->mac);
}

int
is_own_ip_addr(struct l3_interfaces *l3ifs, uint32_t addr)
{
  uint16_t len = l3ifs->len;  
  struct l3_interface *l3_list = l3ifs->list;
  for(uint16_t i = 0; i < len; i++) {
    struct l3_interface *l3if = &l3_list[i];
    if(!(l3if->ip_addr ^ addr)) return 1;
  }
  return 0;
}

int
is_own_subnet(struct l3_interfaces *l3ifs, uint32_t addr)
{
  uint16_t len = l3ifs->len;
  struct l3_interface *l3_list = l3ifs->list;
  for(uint16_t i = 0; i < len; i++) {
    struct l3_interface *l3if = &l3_list[i];
    if(!((l3if->ip_addr ^ addr) & l3if->ip_mask)) return 1;
  }
  return 0;
}
