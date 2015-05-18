/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if 0
#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#endif

#if 0
#include "util.h"
#include "global_mario.h"
#endif

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER1
#define BUFFER_MAX 1024

#if 0
#define mmalloc(x) rte_malloc("rtrie", (x), 0)
#define mfree(x) rte_free((x))
#endif
#if 1
#define RTE_LOG(x, y, z) ;
#define mmalloc(x) malloc(x)
#define mfree(x) free((x))
#endif

int
parse_port(char *buffer)
{
  uint8_t port_id = (uint8_t) atoi(strtok(NULL, " \t"));
  char *a_ip_addr   = strtok(NULL, " \t");
  uint8_t mask_len = (uint8_t) atoi(strtok(NULL, " \t"));
  uint8_t ip_addr[4];
  
  ip_addr[0] = atoi(strtok(a_ip_addr, "."));
  ip_addr[1] = atoi(strtok(NULL, "."));
  ip_addr[2] = atoi(strtok(NULL, "."));
  ip_addr[3] = atoi(strtok(NULL,  "."));  

  printf("port_id: %u\t", port_id);
  printf("IP address: %u.%u.%u.%u/%u\n",
         ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], mask_len);
  return 0;
}

int parse_route(char *buffer)
{
  char *a_ip_addr  = strtok(NULL, " \t");
  uint8_t mask_len = atoi(strtok(NULL, " \t"));
  char *a_next_hop = strtok(NULL, " \t"); 
  uint8_t ip_addr[4];
  uint8_t next_hop[4];
  
  ip_addr[0] = atoi(strtok(a_ip_addr, "."));
  ip_addr[1] = atoi(strtok(NULL, "."));
  ip_addr[2] = atoi(strtok(NULL, "."));
  ip_addr[3] = atoi(strtok(NULL,  "."));  

  next_hop[0] = atoi(strtok(a_next_hop, "."));
  next_hop[1] = atoi(strtok(NULL, "."));
  next_hop[2] = atoi(strtok(NULL, "."));
  next_hop[3] = atoi(strtok(NULL,  "."));  

  printf("IP address: %u.%u.%u.%u/%u\t",
         ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], mask_len);
  printf("IP address: %u.%u.%u.%u\n",
         next_hop[0], next_hop[1], next_hop[2], next_hop[3]);

  return 0;
}

int
load_config(char* path) {
  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    RTE_LOG(ERR, CONFIG, "cannot open the config file.\n");
    return 1;
  }

  char buffer[BUFFER_MAX];
  while(fgets(buffer, BUFFER_MAX, fp) != NULL ) {
    char* ope = strtok(buffer, " \t");
    if (strcmp(ope, "route") == 0) {
      parse_route(buffer);
    } else if (strcmp(ope, "port") == 0) {
      parse_port(buffer);
    }
  }

  return 0;
}

int main() {
  char path[] = "./test_len.conf";
  load_config(path);
  return 0;
}
  
