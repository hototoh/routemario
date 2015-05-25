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
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lpm.h>

#include "util.h"
#include "interfaces.h"
#include "global_mario.h"

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER1
#define BUFFER_MAX 1024

#if 1
#define mmalloc(x) rte_malloc("rtrie", (x), 0)
#define mfree(x) rte_free((x))
#endif
#if 0
#define RTE_LOG(x, y, z) ;
#define mmalloc(x) malloc(x)
#define mfree(x) free((x))
#endif

struct rte_lpm* rib;
uint32_t next_hop_tb[255];
uint8_t len = 0;
static uint8_t get_next_nhop_index() {
  return len++;
}

static int
parse_port(char *buffer)
{
  uint8_t port_id = (uint8_t) atoi(strtok(NULL, " \t"));
  char *a_ip_addr   = strtok(NULL, " \t");
  uint8_t mask_len = (uint8_t) atoi(strtok(NULL, " \t"));
  uint8_t ip_addrs[4];  
  ip_addrs[0] = atoi(strtok(a_ip_addr, "."));
  ip_addrs[1] = atoi(strtok(NULL, "."));
  ip_addrs[2] = atoi(strtok(NULL, "."));
  ip_addrs[3] = atoi(strtok(NULL,  "."));

  struct l3_interface *l3_if = get_l3_interface_port_id(intfs, port_id);
  if (l3_if == NULL) {
    RTE_LOG(ERR, CONFIG, "Out of range in 3 interfaces.\n");
    return 1;
  }

  struct ether_addr mac;
  rte_eth_macaddr_get(port_id, &mac);
  uint32_t ip_addr = IPv4(ip_addrs[0], ip_addrs[1], ip_addrs[2], ip_addrs[3]); 
  uint32_t ip_mask = (uint32_t) (~(1UL) << (32 - mask_len - 1));
  set_l3_interface(l3_if, 0, &mac, ip_addr, ip_mask, port_id);
  {
    uint32_t s = ip_addr;
    uint32_t m = ip_mask;
    RTE_LOG(INFO, CONFIG,
            "port_id: %u\t %u.%u.%u.%u/%u ( %u.%u.%u.%u )\n", port_id,
            (s >> 24)&0xff,(s >> 16)&0xff,(s >> 8)&0xff,s&0xff, mask_len,
            (m >> 24)&0xff,(m >> 16)&0xff,(m >> 8)&0xff,m&0xff);
  }
  return 0;
}

static int
parse_route(char *buffer)
{
  char *a_ip_addr  = strtok(NULL, " \t");
  uint8_t mask_len = atoi(strtok(NULL, " \t"));
  char *a_next_hop = strtok(NULL, " \t"); 
  uint8_t ip_addrs[4];
  uint8_t next_hops[4];
  
  ip_addrs[0] = atoi(strtok(a_ip_addr, "."));
  ip_addrs[1] = atoi(strtok(NULL, "."));
  ip_addrs[2] = atoi(strtok(NULL, "."));
  ip_addrs[3] = atoi(strtok(NULL,  "."));  

  next_hops[0] = atoi(strtok(a_next_hop, "."));
  next_hops[1] = atoi(strtok(NULL, "."));
  next_hops[2] = atoi(strtok(NULL, "."));
  next_hops[3] = atoi(strtok(NULL,  "."));  

  uint32_t ip_addr = IPv4(ip_addrs[0], ip_addrs[1], ip_addrs[2], ip_addrs[3]); 
  uint32_t ip_mask = (uint32_t) (~(1UL) << (32 - mask_len - 1));
  uint32_t next_hop = IPv4(next_hops[0], next_hops[1],
                           next_hops[2], next_hops[3]);
  uint8_t index = get_next_nhop_index();
  int res = rte_lpm_add(rib, ip_addr, mask_len, index);
  if (res < 0) {
     RTE_LOG(DEBUG, CONFIG, "%s config error res=%d\n", __func__, res);
     sleep(0.5);
  }

  next_hop_tb[index] = next_hop;
  
  RTE_LOG(INFO, CONFIG, 
          "IP address: %u.%u.%u.%u/%u\t"
          "NextHop: %u.%u.%u.%u\n",
          ip_addrs[0], ip_addrs[1], ip_addrs[2], ip_addrs[3], mask_len,
          next_hops[0], next_hops[1], next_hops[2], next_hops[3]);
  return 0;
}

int
load_config(char* path) {
  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    RTE_LOG(ERR, CONFIG, "cannot open the config file.\n");
    return 1;
  }

  if (rib == NULL) {
    RTE_LOG(ERR, CONFIG, "rib must be created before calling load_config.");
    return 1;
  }

  if (intfs == NULL) {
    RTE_LOG(ERR, CONFIG, 
            "l3_interfaces must be created before calling load_config.");
    return 1;
  }

  char buffer[BUFFER_MAX];
  while(fgets(buffer, BUFFER_MAX, fp) != NULL ) {
    char* ope = strtok(buffer, " \t");
    if (strcmp(ope, "route") == 0) {
      if(parse_route(buffer)) return 1;
    } else if (strcmp(ope, "port") == 0) {
      if(parse_port(buffer)) return 1;
    }
  }

  return 0;
}

/* int main() { */
/*   char path[] = "./test_len.conf"; */
/*   load_config(path); */
/*   return 0; */
/* } */
  
