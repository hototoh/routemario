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
#include <rte_log.h>
#include <rte_malloc.h>

#include "util.h"

#define mmalloc(x) rte_malloc("rtrie", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_RADIX RTE_LOGTYPE_USER1
/**
 * +-+-+-+-+-+-+-+-+
 * |1|2|3|4|5|6|7|8|  x = 3, len = 5
 * +-+-+-+-+-+-+-+-+ 
 * | | |*| | | | | |  kth_bit
 * +-+-+-+-+-+-+-+-+
 * |*|*| | | | | | |  upper_kth_bits
 * +-+-+-+-+-+-+-+-+
 * | | | |*|*| | | |  lower_kth_bits
 * +-+-+-+-+-+-+-+-+
 */
#define kth_bit(x, k) ((x >> (sizeof(x)*8 - k)) & 1) 
#define upper_kth_bits(x, k) \
  (x >> (sizeof(x)*8 - k + 1)
#define lower_kth_bits(x, k, len)                  \
  ((x >> (sizeof(x)*8 - len)) & ((1 << (len -k)) - 1)

static inline uint8_t
get_head_bit(uint8_t len, uint16_t max)
{
  if (len >= max)
    len = generic_fls(max);
  return len;
}

static inline struct radix_trie**
get_radix_tire_haed_ptr(struct radix_trie* trie, uint8_t *key, uint16_t cur)
{
  uint16_t head_index = 16 - cur;
  return &trie->heads[head_index];
}

static inline struct radix_trie*
get_radix_tire_haed(struct radix_trie* trie, uint8_t *key, uint16_t cur)
{
  uint16_t head_index = 16 - cur;
  return trie->heads[head_index];
}

struct radix_trie*
create_radix_trie(uint16_t len)
{
  uint8_t size = POWERROUND(len);
  struct radix_trie *trie;
  trie = (struct radix_trie*) mmalloc(sizeof(struct radix_trie) +
                                      sizeof(struct radix_trie_node) * size);
  if (trie == NULL) {
    RTE_LOG(ERR, RADIX, "cannot allocate memory for trie.\n");
    return NULL;
  }

  trie->len = size;
  return trie;
}

void
destroy_radix_trie(struct radix_trie *trie)
{
  mfree(trie);
}

static struct radix_trie_node *
create_radix_trie_node(uint8_t len, uint16_t prefix) 
{
  struct radix_trie_node *node;
  node = (struct radix_trie_node *) mmalloc(sizeof(struct radix_trie_node));
  if (node == NULL) {
    RTE_LOG(ERR, RADIX, "cannot allocate memory for trie node.\n");
    return NULL;
  }

  node->prefix  = (uint8_t) prefix;
  node->len     = len;
  node->next[0] = NULL;
  node->next[1] = NULL;
  node->next    = NULL;
  return node;
}

/* @cur point the previous bit index */
static struct radix_trie_node *
build_radix_sub_trie(uint8_t *key, uint8_t len, uin16_t cur, void* item)
{
  struct radix_trie_node *node = NULL, *head = NULL, **pnode = NULL;
  while(cur < len) {
    // prefix len
    uint8_t nlen = 8;
    if (cur + 8 > len) nlen = len - cur; // smaller than 8
    
    // prefix
    uint8_t prefix = 0;
    for(uint8_t i = 1; i <= nlen; i++) {
      if (!(++cur & PREFIX_MASK_SIZE)) key++;      
      uint8_t tmp = (kth_bit(*key, (cur & PREFIX_MASK_SIZE)) << (8-i));
      prefix += tmp;      
    }
    struct radix_trie_node *nnode = create_radix_trie_node(nlen, prefix);
    if (head == NULL) head = node = nnode;
    else {
      *pnode = nnode;
      node = nnode;
    }

    if (cur == len) {
      nnode->item = item;
      break;
    }

    if (!(++cur & PREFIX_MASK_SIZE)) key++;      
    uint8_t next_node_bit = kth_bit(*key, (cur & PREFIX_MASK_SIZE));
    pnode = &node->next[next_node_bit];
  }

  return head;
}



int
radix_trie_insert_item(struct radix_trie *trie, uint8_t* key,
                       uint8_t len, void* item)
{
  uint8_t key_bit;
  void *item = NULL;
  uint16_t cur = get_head_bit(len, trie->len);
  uint16_t head_index = get_head_index(key, cur);
  struct radix_trie_node **pnode = get_head_node_ptr(trie, key, len);  
  struct radix_trie_node *node  = *pnode;
  
  while (node != NULL) {
    if (!(++cur & PREFIX_MASK_SIZE)) key++;
    if (cur > len) {
      (*pnode)->item = item;
      goto out;
    }

    /* check aggregated node */
    bool split_flag = false;
    uint16_t preifx = node->prefix;
    uint8_t nlen = node->len;
    for(uint8_t i = 1; i <= nlen; i++) {
      uint16_t bit = kth_bit(prefix, i);
      if (!(++cur & PREFIX_MASK_SIZE)) key++;      
      if (cur <= len) {
        key_bit = kth_bit(*key, (cur & PREFIX_MASK_SIZE));
        if (bit ^ key_bit) continue;
      }

      /* split node here */
      uint16_t nprefix = upper_kth_bits(prefix, i, len) << (8 -i+1);
      struct radix_trie_node* nnode = create_radix_trie_node(i-1, nprefix);
      if (nnode == NULL) {
        RTE_LOG(ERR, RADIX, "fail to add node.\n");
        return 1;
      }
      
      node->len = len - i;
      node->prefix = lower_kth_bits(prefix, i, len) << (8 - len);
      nnode->next[bit] = node;
      *pnode = nnode;
      node = nnode;
      if (cur < len) break;
      
      // cur > len
      nnode->item = item;
      goto out;
    }

    key_bit = kth_bit(*key, (cur & PREFIX_MASK_SIZE));
    pnode = &node->next[key_bit];
    node = *pnode;
  }

  struct radix_trie_node* nnode = build_radix_sub_trie(key, len, cur, item);
  if (nnode == NULL) {
    RTE_LOG(ERR, RADIX, "fail to add node.\n");
    return 1;
  }
  *pnode = node;
  
out:
  return 0;
}

void *
radix_trie_lookup_item(struct radix_trie *trie, uint8_t* key,
                       uint8_t len, void* item)
{

}

void
radix_trie_delete_item(struct radix_trie *trie, uint8_t key, uint8_t len)
{
  uint16_t head_index = get_head_index(key, len, trie->len);
  struct radix_node *head = get_head_node(trie, key, len);
  
}
