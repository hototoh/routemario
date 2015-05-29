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
#include <arpa/inet.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_ethdev.h>

#include "bit_utils.h"
#include "interfaces.h"
#include "global_mario.h"

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
  RTE_LOG(ERR, L3IF, "create %u ports\n", len);
  memset(l3_ifs, 0, size);
  l3_ifs->len = 0;
  l3_ifs->max = len;
  return l3_ifs;
}

void
destroy_l3_interfaces(struct l3_interfaces *l3_ifs)
{
  mfree(l3_ifs);
}

struct l3_interface *
get_l3_interface_port_id(struct l3_interfaces *l3_ifs, uint8_t port_id) {
  if (l3_ifs->len >=l3_ifs->max) return NULL;
  struct l3_interface *l3_if = l3_ifs->list;
  
  return &l3_ifs->list[port_id];
}

void
set_l3_interface(struct l3_interface *l3if, const uint16_t vlan_id,
                 const struct ether_addr *addr, const uint32_t ip_addr,
                 const uint32_t ip_mask,  const uint8_t port_id)
{
  l3if->vlan_id = vlan_id;
  l3if->ip_addr = ip_addr;
  l3if->port_id = port_id;
  l3if->ip_mask = ip_mask;
  ether_addr_copy(addr, &l3if->mac);
}

int
is_own_ip_addr(struct l3_interfaces *l3ifs, uint32_t addr)
{
  uint16_t len = l3ifs->max;  
  struct l3_interface *l3_list = l3ifs->list;
  for(uint16_t i = 0; i < len; i++) {
    struct l3_interface *l3if = &l3_list[i];
    if (l3if == NULL) continue;
    if(!(l3if->ip_addr ^ addr)) return l3if->port_id;
  }
  return -1;
}

int
is_own_subnet(struct l3_interfaces *l3ifs, uint32_t addr)
{
  
  uint16_t len = l3ifs->max;
  struct l3_interface *l3_list = l3ifs->list;
  for(uint16_t i = 0; i < len; i++) {
    struct l3_interface *l3if = &l3_list[i];
    if (l3if == NULL) continue;
#ifndef NDEBUG
    {
      uint32_t s = l3if->ip_addr;
      uint32_t d = addr;
      uint32_t x = l3if->ip_addr ^ addr;
      uint32_t m = l3if->ip_mask;
      uint32_t r = x & m;
      RTE_LOG(INFO, L3IF,
              "\nsrc  :%u.%u.%u.%u"
              "\ndst  :%u.%u.%u.%u"
              "\nmask :%u.%u.%u.%u"
              "\nxor  :%u.%u.%u.%u"
              "\nres  :%u.%u.%u.%u\n",
              (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff,
              (d >> 24)&0xff,(d>> 16)&0xff,(d >> 8)&0xff,d&0xff,
              (m >> 24)&0xff,(m>> 16)&0xff,(m >> 8)&0xff,m&0xff,
              (x >> 24)&0xff,(x >> 16)&0xff,(x >> 8)&0xff,x&0xff,
              (r >> 24)&0xff,(r>> 16)&0xff,(r >> 8)&0xff,r&0xff);
    }
#endif
    if(!((l3if->ip_addr ^ addr) & l3if->ip_mask)) {
      return l3if->port_id;
    }
  }
  return -1;
}

struct ether_addr*
get_macaddr_with_port(struct l3_interfaces * l3ifs, uint8_t port_id)
{
  struct ether_addr* mac;
  uint16_t len = l3ifs->max;
  if (port_id >= len) {
    RTE_LOG(DEBUG, L3IF, "port_id %u is out of range\n", port_id);
    return NULL;
  }

  struct l3_interface* l3if = &l3ifs->list[port_id];
  if (l3if == NULL) {
    RTE_LOG(DEBUG, L3IF, "L3 interface is not found\n");
    return NULL;
  }
  return &l3if->mac;
}
    
