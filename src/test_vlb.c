/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include "vlb.h"

#define RTE_LOGTYPE_VLB_TEST RTE_LOGTYPE_USER1

#define MAX_UINT32  ((uint32_t)~0UL)

uint8_t _mid = 1;

int main(int argc, char **argv) {
  int ret;
  ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

  for (uint32_t i = 0; i < MAX_UINT32; i++) {
    uint8_t node_id = forwarding_node_id(i);
    RTE_LOG(INFO, VLB_TEST, "%u, node_id: %u\n", i, node_id);
  }
  for (uint32_t i = 0; i < MAX_UINT32; i++) {
    uint8_t node_id = forwarding_node_id(i);
    RTE_LOG(INFO, VLB_TEST, "%u, node_id: %u\n", i, node_id);
  }
  uint64_t now = rte_get_timer_cycles();
  uint64_t gap = now - rte_get_timer_cycles();

  RTE_LOG(DEBUG, VLB_TEST, "gap %lu\n", gap);
}
