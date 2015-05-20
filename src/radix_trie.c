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
#include "trie.h"

#define mmalloc(x) rte_malloc("rtrie", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_RADIX RTE_LOGTYPE_USER1
/**
 * +-+-+-+-+-+-+-+-+                  +-+-+-+-+-+-+-+-+
 * |1|2|3|4|5|6|7|8|  x = 3, len = 6  |1|2|3|4|5|6|7|8|
 * +-+-+-+-+-+-+-+-+                  +-+-+-+-+-+-+-+-+
 * | | |*| | | | | |  kth_bit         | | | | | | | |*|
 * +-+-+-+-+-+-+-+-+                  +-+-+-+-+-+-+-+-+
 * |*|*| | | | | | |  upper_kth_bits  |*|*| | | | | | |
 * +-+-+-+-+-+-+-+-+                  +-+-+-+-+-+-+-+-+
 * | | | |*|*|*| | |  lower_kth_bits  |*|*|*| | | | | |
 * +-+-+-+-+-+-+-+-+                  +-+-+-+-+-+-+-+-+
 */

#define top_kbit_mask(k) ((uint32_t) (~0UL << (32-k)))
#define lower_kbit_mask(k) (~((uint32_t) (~0UL << (k))))
#define kth_bit(x, k) ((x >> (32 - k)) & 1) 
#define upper_kth_bits(x, k) (x & top_kbit_mask(k-1))
#define lower_kth_bits(x, k)  (x << (k))


static inline uint8_t
get_head_bit(uint8_t len, uint16_t max)
{
  if (len >= max)
    len = generic_fls(max);
  return len;
}

static inline struct radix_trie_node**
get_radix_tire_haed_ptr(struct radix_trie* trie, uint8_t *key, uint16_t cur)
{
  uint16_t head_index = 16 - cur;
  return &trie->heads[head_index];
}

static inline struct radix_trie_node*
get_radix_tire_haed(struct radix_trie* trie, uint8_t *key, uint16_t cur)
{
  uint16_t head_index = 16 - cur;
  return trie->heads[head_index];
}

void
destroy_radix_trie(struct radix_trie_node *trie)
{
  // XXX traverse tree
  mfree(trie);
}

struct radix_trie_node *
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
  return node;
}

static struct radix_trie_node *
build_radix_sub_trie(uint8_t *key, uint8_t len, uint16_t cur, void* item)
{

}

int
radix_trie_insert_item(struct radix_trie *root, 
                       uint32_t key, uint8_t len, void* item)
{ 
  uint8_t cur_index = 0;
  struct radix_trie_node* node = root, **pnode = NULL;
  
  while(node != NULL) {
    uint8_t prefix_len = len - cur_index;
    if (node->len > prefix_len) {
      uint32_t prefix = (node->prefix << cur_index) & top_kbit_mask(prefix_len);
      uint32_t node_prefix = node->prefix & top_kbit_mask(prefix_len);
      uint32_t xor_prefix = node_prefix ^ prefix;
      // almost same process under the else
      if (xor_prefix) {
        ;
        
      } else {
        ;
      }
    } else {
      uint32_t prefix = (node->prefix << cur_index) & top_kbit_mask(node->len);
      uint32_t xor_prefix = node->prefix ^ prefix;
      if (xor_prefix) { // add new node & branch node.
        // an index from left for prefix separation 
        uint8_t  div_index = (uint8_t) (32 - generic_fls(xor_prefix) + 1);
        uint8_t  old_node_index = kth_bit(node->prefix, div_index);
        uint8_t  new_node_len = len - cur_index - div_index;
        uint32_t new_node_prefix =  lower_kth_bits(prefix, div_index);
        uint32_t common_upper_prefix = upper_kth_bits(prefix, div_index);
        uint32_t old_lower_prefix = lower_kth_bits(node->prefix, div_index);
        struct radix_trie_node *branch_node = 
            create_radix_trie_node(div_index - 1, common_upper_prefix);
        branch_node->next[old_node_index] = node;         
        branch_node->next[(old_node_index ^ 1)] = 
            create_radix_trie_node(new_node_len, new_node_prefix);
        node->len -= div_index;
        node->prefix = old_lower_prefix;        
        *pnode = branch_node;
      } else {
        cur_index += node->len;
        if (cur_index++ == len) { 
          // this node is the designated node.
          // override the existing item.
          node->item = item;
          return 0;
        }
        // cur_index < len;
        uint8_t next_bit = kth_bit(key, cur_index);
        pnode = &node->next[next_bit];
        node = node->next[next_bit];            
      }
    }
  }

  *pnode = new_node;

  return 0;
}

static inline void
set_node_item_if_exists(struct radix_trie_node *node,  void **item)
{
  if (root->item != NULL) *item = node->item;
}

void *
radix_trie_lookup_item(struct radix_trie *root, uint32_t key)
{
  void *lpm_item;
  uint8_t cur_index = 0;
  struct radix_trie_node* node = root;
  
  while(node != NULL) {
    set_node_item_if_exists(node, &lpm_item);
    
    // check prefix of node
    uint32_t prefix = (node->prefix << cur_index) & top_kbit_mask(node->len);
    if (node->prefix ^ prefix) break;
    ++cur_index;

    uint8_t next_bit = kth_bit(key, cur_index);
    node = node->next[next_bit];
  }

  return lpm_item;
}

void
radix_trie_delete_item(struct radix_trie *root, uint32_t key, uint8_t len)
{
  
}
