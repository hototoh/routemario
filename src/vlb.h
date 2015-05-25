#ifndef VLB_H
#define VLB_H

#include <stdint.h>

struct vlb_info {
  uint8_t node_id;
  uint64_t expire;
};

uint8_t forwarding_node_id(uint32_t rss);

#endif
