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
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_log.h>

#include "mbuf_queue.h"

#define RTE_LOGTYPE_MBUF_Q RTE_LOGTYPE_USER1

#define mmalloc(x) rte_malloc("L3IF", (x), 0)
#define mfree(x) rte_free((x))

struct mbuf_queue*
create_mbuf_queue(uint16_t len)
{
  struct mbuf_queue *queue;
  size_t size = sizeof(struct mbuf_queue) +
                sizeof(struct rte_mfbuf*) * len;
  queue = (struct mbuf_queue*) mmalloc(size);
  if (queue == NULL) {
    RTE_LOG(ERR, MBUF_Q, "cannot allocate mmeory\n");
    return NULL;
  }
  
  queue->len = 0;
  queue->max = len;
  return queue;
}

void
destroy_mbuf_queue(struct mbuf_queue *queue)
{
  mfree(queue);
}



